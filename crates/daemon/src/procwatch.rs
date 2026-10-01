//! Periodic /proc scan that SIGKILLs processes matching any active block.
//!
//! Guard set, checked before a process is even identified (see
//! [`is_protected`]): pid 0 and 1, this daemon's own pid, kernel threads, and
//! anything running as root are never signalled. Root is skipped outright —
//! systemd, logind, our own `nft`/`chattr` children — rather than `uid <
//! UID_MIN`, because `UID_MIN` is distro-configurable and a wrong boundary
//! would silently stop blocking the user's own apps. The cost is documented:
//! an app launched through `sudo`/`pkexec` runs as euid 0 and survives a
//! block. Matchers are additionally re-canonicalized on every tick
//! ([`enforced_groups`]), so an entry that would match GrepFocus itself or
//! nearly every process never reaches the sweep.

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use grepfocus_core::validate::{matcher_text, normalize_matcher};
use grepfocus_core::{now_unix, ActiveBlock, AppMatcher, EventKind};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use procfs::process::{all_processes, StatFlags};
use tracing::{debug, warn};

use crate::Daemon;

const POLL_INTERVAL: Duration = Duration::from_millis(500);

pub async fn run(daemon: Arc<Daemon>) {
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // PIDs killed on the PREVIOUS tick, so the same process isn't counted as
    // a fresh kill every 500 ms while it lingers (dying) in the table. Cleared
    // when the pid disappears (it's simply absent from the next tick's set),
    // so a later PID reuse counts again. Kept in the loop, not on `Daemon`,
    // because only this task needs it.
    let mut recently_killed: HashSet<i32> = HashSet::new();
    // Read once: the pid never changes, and the sweep must never signal it.
    let self_pid = std::process::id() as i32;
    loop {
        ticker.tick().await;
        let groups = {
            let st = daemon.state.lock().await;
            if st.active.is_empty() {
                recently_killed.clear();
                continue;
            }
            enforced_groups(&st.active, now_unix())
        };
        if groups.is_empty() {
            recently_killed.clear();
            continue;
        }
        // /proc scanning is sync; do it on a blocking thread so we don't
        // stall the runtime.
        let killed = match tokio::task::spawn_blocking(move || sweep(&groups, self_pid)).await {
            Ok(k) => k,
            Err(e) => {
                warn!(?e, "sweep task panicked");
                continue;
            }
        };
        // Count only PIDs not already killed last tick, so a distinct process
        // is counted once per continuous presence. Accumulate in memory; the
        // scheduler tick folds this into today's rollup on its next save.
        // Each new kill is also one event for `GetStatus.recent_events`,
        // pushed under the events leaf lock alone — no other lock is held
        // here.
        let new = new_kills(&killed, &recently_killed);
        if !new.is_empty() {
            daemon
                .app_kills_pending
                .fetch_add(new.len() as u64, Ordering::Relaxed);
            let now = now_unix();
            let mut events = daemon.events();
            for k in &new {
                events.push(EventKind::AppKill, k.block_id, &k.label, now);
            }
        }
        recently_killed = killed.iter().map(|k| k.pid).collect();
    }
}

/// One process the sweep killed: for the per-PID dedup, the stats counter
/// and the event log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kill {
    pub pid: i32,
    /// The block whose matcher claimed it (first matching group).
    pub block_id: u64,
    /// What to call it on the wire — see [`kill_label`].
    pub label: String,
}

/// The user-facing name for a kill: the text of the matcher that claimed the
/// process, which is the user's own blocklist entry — `name` for a basename,
/// the file name of an exe path (the whole path if it has none), the pattern
/// for a cmdline match. Deliberately never the process's own `/proc` text:
/// that is what goes on every status frame and into a notification, and the
/// user wrote this one.
fn kill_label(m: &AppMatcher) -> String {
    match m {
        AppMatcher::ExePath { path } => Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(path)
            .to_string(),
        AppMatcher::Basename { .. } | AppMatcher::Cmdline { .. } => matcher_text(m).to_string(),
    }
}

/// The app matchers to enforce right now, grouped BY BLOCK so a kill can be
/// attributed to the block that matched it. Includes apps from active blocks
/// that (a) snapshotted app enforcement at activation (`apps_enforced` — set
/// from the license's `app_blocking` feature at that moment, so a mid-block
/// license change in either direction never alters a running block) and
/// (b) are not currently on a break. Each matcher passes through
/// `normalize_matcher`, so one that would match GrepFocus itself, or nearly
/// every process, is left out even if a stored copy still carries it; blocks
/// with no matchers left are dropped. Pure, so the enforcement decision is
/// unit-testable without a live `/proc`.
fn enforced_groups(active: &[ActiveBlock], now: u64) -> Vec<(u64, Vec<AppMatcher>)> {
    active
        .iter()
        .filter(|a| a.apps_enforced)
        // Skip blocks currently on a break — their apps run freely.
        .filter(|a| a.break_until_unix.is_none_or(|t| t <= now))
        .filter_map(|a| {
            let apps: Vec<AppMatcher> = a
                .block
                .apps
                .iter()
                .filter_map(|m| normalize_matcher(m).ok())
                .collect();
            (!apps.is_empty()).then_some((a.block.id, apps))
        })
        .collect()
}

/// Whether a process is off limits to the sweep regardless of what it runs:
/// pid 0 (the idle task) and 1 (init), this daemon itself, a kernel thread,
/// or anything whose effective uid is root (system services, setuid helpers,
/// our own child processes, and — the documented cost — an app launched via
/// `sudo`/`pkexec`). Pure, so the guard set is unit-testable.
fn is_protected(pid: i32, uid: u32, kthread: bool, self_pid: i32) -> bool {
    pid <= 1 || pid == self_pid || kthread || uid == 0
}

/// The kills in `killed` whose PID was NOT killed on the previous tick.
/// Pure, so the per-PID dedup is unit-testable without a live `/proc`.
fn new_kills<'a>(killed: &'a [Kill], recently_killed: &HashSet<i32>) -> Vec<&'a Kill> {
    killed
        .iter()
        .filter(|k| !recently_killed.contains(&k.pid))
        .collect()
}

/// Scan `/proc`, SIGKILL every unprotected process matching any group's
/// matchers, and return the processes actually killed this tick (used for
/// dedup, the kill count and the event log). ESRCH (already gone) is not
/// counted — nothing was killed.
///
/// The guard runs before the process is identified, so `exe`/`cmdline` are
/// never read for a protected one. A process that vanished between the
/// listing and any read here is skipped: it is gone either way.
fn sweep(groups: &[(u64, Vec<AppMatcher>)], self_pid: i32) -> Vec<Kill> {
    let mut killed = Vec::new();
    let procs = match all_processes() {
        Ok(p) => p,
        Err(e) => {
            warn!(?e, "all_processes() failed");
            return killed;
        }
    };
    for proc in procs.flatten() {
        let pid = proc.pid();
        // One fstat of the pid directory. This is the EFFECTIVE uid: the
        // kernel exempts the top-level pid dir from the non-dumpable→root
        // ownership rule (`task_dump_owner`), so a setuid or ptrace-protected
        // process still reports the user it runs as.
        let Ok(uid) = proc.uid() else {
            continue;
        };
        // `stat` is read once and reused for `comm` below; the PF_KTHREAD
        // flag is a belt over the uid rule (every kernel thread is uid 0).
        let Ok(stat) = proc.stat() else {
            continue;
        };
        let kthread = stat.flags & StatFlags::PF_KTHREAD.bits() != 0;
        if is_protected(pid, uid, kthread, self_pid) {
            continue;
        }
        let exe = proc.exe().ok();
        let cmdline = proc.cmdline().ok();
        // First matching group attributes the kill, and its first matching
        // entry names it; one SIGKILL is enough.
        let Some((block_id, matcher)) = groups.iter().find_map(|(block_id, m)| {
            matching_entry(exe.as_deref(), cmdline.as_deref(), Some(&stat.comm), m)
                .map(|matcher| (*block_id, matcher))
        }) else {
            continue;
        };
        debug!(pid, block_id, "killing process");
        match kill(Pid::from_raw(pid), Signal::SIGKILL) {
            Ok(()) => killed.push(Kill {
                pid,
                block_id,
                label: kill_label(matcher),
            }),
            Err(nix::errno::Errno::ESRCH) => {} // already gone; nothing killed
            Err(e) => warn!(?e, pid, "SIGKILL failed"),
        }
    }
    killed
}

/// Pure matcher over a process's identity fields, split out so it can be
/// tested without a live `/proc`: the first entry in `matchers` that matches,
/// so a kill can be named after the entry that claimed it. `exe` is the
/// resolved `/proc/<pid>/exe`, `cmdline` its argv, `comm` the kernel `comm`
/// name.
fn matching_entry<'a>(
    exe: Option<&Path>,
    cmdline: Option<&[String]>,
    comm: Option<&str>,
    matchers: &'a [AppMatcher],
) -> Option<&'a AppMatcher> {
    matchers.iter().find(|m| match m {
        AppMatcher::ExePath { path } => exe == Some(Path::new(path)),
        AppMatcher::Basename { name } => {
            exe.is_some_and(|p| p.file_name().and_then(|n| n.to_str()) == Some(name.as_str()))
                // Fallback to the kernel comm name (e.g. for kernel-truncated
                // or wrapper processes whose exe basename differs).
                || comm == Some(name.as_str())
        }
        AppMatcher::Cmdline { contains } => {
            cmdline.is_some_and(|parts| parts.join(" ").contains(contains.as_str()))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether any entry matches — the yes/no the matcher tests below ask.
    fn proc_matches(
        exe: Option<&Path>,
        cmdline: Option<&[String]>,
        comm: Option<&str>,
        matchers: &[AppMatcher],
    ) -> bool {
        matching_entry(exe, cmdline, comm, matchers).is_some()
    }

    #[test]
    fn exe_path_matches_exactly() {
        let m = [AppMatcher::ExePath {
            path: "/usr/bin/steam".into(),
        }];
        assert!(proc_matches(
            Some(Path::new("/usr/bin/steam")),
            None,
            None,
            &m
        ));
        assert!(!proc_matches(
            Some(Path::new("/usr/bin/other")),
            None,
            None,
            &m
        ));
        assert!(!proc_matches(None, None, None, &m));
    }

    #[test]
    fn basename_matches_via_exe() {
        let m = [AppMatcher::Basename {
            name: "steam".into(),
        }];
        assert!(proc_matches(
            Some(Path::new("/usr/games/steam")),
            None,
            None,
            &m
        ));
        assert!(!proc_matches(
            Some(Path::new("/usr/games/steamworks")),
            None,
            None,
            &m
        ));
    }

    #[test]
    fn basename_falls_back_to_comm() {
        let m = [AppMatcher::Basename {
            name: "steam".into(),
        }];
        // exe basename differs, but comm matches.
        assert!(proc_matches(
            Some(Path::new("/usr/bin/wrapper")),
            None,
            Some("steam"),
            &m
        ));
        // exe unavailable, comm matches.
        assert!(proc_matches(None, None, Some("steam"), &m));
        // neither matches.
        assert!(!proc_matches(
            Some(Path::new("/usr/bin/wrapper")),
            None,
            Some("other"),
            &m
        ));
    }

    #[test]
    fn cmdline_matches_substring() {
        let m = [AppMatcher::Cmdline {
            contains: "com.discordapp.Discord".into(),
        }];
        let parts = [
            "/usr/bin/flatpak".to_string(),
            "run".to_string(),
            "com.discordapp.Discord".to_string(),
        ];
        assert!(proc_matches(None, Some(&parts), None, &m));
        assert!(!proc_matches(
            None,
            Some(&["firefox".to_string()]),
            None,
            &m
        ));
        assert!(!proc_matches(None, None, None, &m));
    }

    #[test]
    fn no_matchers_never_matches() {
        assert!(!proc_matches(
            Some(Path::new("/usr/bin/steam")),
            Some(&["steam".to_string()]),
            Some("steam"),
            &[]
        ));
    }

    // ── enforced_matchers() ─────────────────────────────────────────────────

    use grepfocus_core::{Block, LockMode, Originator};

    fn active(apps_enforced: bool, break_until_unix: Option<u64>) -> ActiveBlock {
        ActiveBlock {
            block: Block {
                id: 1,
                name: "games".into(),
                domains: vec![],
                apps: vec![AppMatcher::Basename {
                    name: "steam".into(),
                }],
                allowance_secs_per_day: 0,
                allowance: None,
                lock: LockMode::Unlocked,
            },
            started_at_unix: 0,
            ends_at_unix: u64::MAX,
            originator: Originator::Manual,
            break_until_unix,
            allowance: None,
            apps_enforced,
            lock: LockMode::Unlocked,
            attempts: 0,
        }
    }

    #[test]
    fn apps_enforced_snapshot_gates_matchers() {
        // apps_enforced=false (free-tier activation, or a pre-gating record
        // via the serde default): the block's apps are NOT enforced, even
        // though the block itself carries matchers.
        assert!(enforced_groups(&[active(false, None)], 100).is_empty());
        // apps_enforced=true: the block's matchers flow through, tagged with
        // the block id for attribution.
        let g = enforced_groups(&[active(true, None)], 100);
        assert_eq!(
            g,
            vec![(
                1,
                vec![AppMatcher::Basename {
                    name: "steam".into()
                }]
            )]
        );
        // Mixed: only the enforcing block contributes a group.
        let g = enforced_groups(&[active(false, None), active(true, None)], 100);
        assert_eq!(g.len(), 1);
    }

    #[test]
    fn breaks_still_suspend_enforced_matchers() {
        // On a break (break_until > now): suspended.
        assert!(enforced_groups(&[active(true, Some(200))], 100).is_empty());
        // Break elapsed: enforcement resumes.
        assert_eq!(enforced_groups(&[active(true, Some(100))], 100).len(), 1);
    }

    /// A stored copy that still carries an entry the validator refuses — one
    /// aimed at GrepFocus itself, a two-character cmdline pattern that would
    /// match nearly everything, a relative exe path — contributes nothing,
    /// and its untrimmed neighbour reaches the sweep in canonical form.
    #[test]
    fn enforced_groups_drops_invalid_matchers() {
        let mut a = active(true, None);
        a.block.apps = vec![
            AppMatcher::Basename {
                name: "  steam  ".into(),
            },
            AppMatcher::Basename {
                name: "grepfocus-gui".into(),
            },
            AppMatcher::Cmdline {
                contains: "GrepFocus".into(),
            },
            AppMatcher::Cmdline {
                contains: "ab".into(),
            },
            AppMatcher::ExePath {
                path: "usr/bin/discord".into(),
            },
            AppMatcher::ExePath {
                path: "/usr/bin/grepfocusd".into(),
            },
            AppMatcher::Basename { name: "".into() },
        ];
        assert_eq!(
            enforced_groups(&[a], 100),
            vec![(
                1,
                vec![AppMatcher::Basename {
                    name: "steam".into()
                }]
            )]
        );
        // Nothing valid left: no group at all, not an empty one.
        let mut a = active(true, None);
        a.block.apps = vec![AppMatcher::Basename {
            name: "grepfocusd".into(),
        }];
        assert!(enforced_groups(&[a], 100).is_empty());
    }

    // ── is_protected(): the guard set ───────────────────────────────────────

    #[test]
    fn is_protected_matrix() {
        const SELF: i32 = 4242;
        // pid 0 (idle task) and 1 (init), whoever they run as.
        assert!(is_protected(0, 1000, false, SELF));
        assert!(is_protected(1, 1000, false, SELF));
        assert!(is_protected(1, 0, false, SELF));
        // The daemon itself.
        assert!(is_protected(SELF, 1000, false, SELF));
        assert!(is_protected(SELF, 0, false, SELF));
        // Kernel threads, even with an unexpected uid.
        assert!(is_protected(2, 1000, true, SELF));
        assert!(is_protected(2, 0, true, SELF));
        // Root, whatever its pid — including a sudo-launched app.
        assert!(is_protected(2, 0, false, SELF));
        assert!(is_protected(99_999, 0, false, SELF));
        // Everything else is fair game: the user, another user, nobody.
        assert!(!is_protected(2, 1000, false, SELF));
        assert!(!is_protected(SELF + 1, 1000, false, SELF));
        assert!(!is_protected(2, 1001, false, SELF));
        assert!(!is_protected(2, 65534, false, SELF));
        // A system account that is not root is not exempt: the boundary is
        // uid 0, deliberately not UID_MIN.
        assert!(!is_protected(2, 1, false, SELF));
        assert!(!is_protected(2, 999, false, SELF));
    }

    // ── new_kills(): per-PID dedup across ticks ─────────────────────────────

    /// The loop's own rebuild of `recently_killed` from a tick's kills.
    fn pids(killed: &[Kill]) -> HashSet<i32> {
        killed.iter().map(|k| k.pid).collect()
    }

    fn kills(pids: &[i32]) -> Vec<Kill> {
        pids.iter()
            .map(|&pid| Kill {
                pid,
                block_id: 1,
                label: "steam".into(),
            })
            .collect()
    }

    #[test]
    fn same_pid_counts_once_new_pid_counts_again() {
        let new_pids = |killed: &[Kill], recently: &HashSet<i32>| {
            new_kills(killed, recently)
                .iter()
                .map(|k| k.pid)
                .collect::<Vec<i32>>()
        };

        // Tick 1: two fresh kills, nothing seen before → both count.
        let mut recently = HashSet::new();
        let killed = kills(&[10, 20]);
        assert_eq!(new_pids(&killed, &recently), vec![10, 20]);
        recently = pids(&killed);

        // Tick 2: the same PIDs still lingering → none count again.
        let killed = kills(&[10, 20]);
        assert!(new_pids(&killed, &recently).is_empty());
        recently = pids(&killed);

        // Tick 3: one lingering, one brand-new PID → only the new one counts,
        // and it comes back whole (block and label) for the event log.
        let killed = kills(&[10, 30]);
        assert_eq!(new_kills(&killed, &recently), vec![&killed[1]]);
        recently = pids(&killed);

        // The PID disappears (empty tick clears it), then a reused PID with
        // the same number reappears → it counts again.
        let killed = kills(&[]);
        assert!(new_pids(&killed, &recently).is_empty());
        recently = pids(&killed);
        let killed = kills(&[10]);
        assert_eq!(new_pids(&killed, &recently), vec![10]);
    }

    // ── kill_label(): what a kill is called on the wire ─────────────────────

    #[test]
    fn kill_label_per_matcher_kind() {
        assert_eq!(
            kill_label(&AppMatcher::Basename {
                name: "steam".into()
            }),
            "steam"
        );
        assert_eq!(
            kill_label(&AppMatcher::ExePath {
                path: "/usr/bin/discord".into()
            }),
            "discord"
        );
        // A path with no file name falls back to the path itself rather than
        // an empty label.
        assert_eq!(kill_label(&AppMatcher::ExePath { path: "/".into() }), "/");
        assert_eq!(
            kill_label(&AppMatcher::Cmdline {
                contains: "com.discordapp.Discord".into()
            }),
            "com.discordapp.Discord"
        );
    }

    /// The entry that names a kill is the first one that matches, in the
    /// block's own order — so the label is the user's text, and predictable.
    #[test]
    fn matching_entry_is_the_first_hit_in_order() {
        let m = [
            AppMatcher::Cmdline {
                contains: "nomatch".into(),
            },
            AppMatcher::Basename {
                name: "steam".into(),
            },
            AppMatcher::ExePath {
                path: "/usr/games/steam".into(),
            },
        ];
        assert_eq!(
            matching_entry(Some(Path::new("/usr/games/steam")), None, None, &m),
            Some(&m[1])
        );
        assert_eq!(matching_entry(None, None, None, &m), None);
    }
}
