//! Periodic /proc scan that SIGKILLs processes matching any active block.

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use grepfocus_core::{now_unix, ActiveBlock, AppMatcher};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use procfs::process::all_processes;
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
        let killed = match tokio::task::spawn_blocking(move || sweep(&groups)).await {
            Ok(k) => k,
            Err(e) => {
                warn!(?e, "sweep task panicked");
                continue;
            }
        };
        // Count only PIDs not already killed last tick, so a distinct process
        // is counted once per continuous presence. Accumulate in memory; the
        // scheduler tick folds this into today's rollup on its next save.
        let new_kills = count_new_kills(&killed, &recently_killed);
        if new_kills > 0 {
            daemon
                .app_kills_pending
                .fetch_add(new_kills as u64, Ordering::Relaxed);
        }
        recently_killed = killed;
    }
}

/// The app matchers to enforce right now, grouped BY BLOCK so a kill can be
/// attributed to the block that matched it. Includes apps from active blocks
/// that (a) snapshotted app enforcement at activation (`apps_enforced` — set
/// from the license's `app_blocking` feature at that moment, so a mid-block
/// license change in either direction never alters a running block) and
/// (b) are not currently on a break. Blocks with no matchers are dropped.
/// Pure, so the enforcement decision is unit-testable without a live `/proc`.
fn enforced_groups(active: &[ActiveBlock], now: u64) -> Vec<(u64, Vec<AppMatcher>)> {
    active
        .iter()
        .filter(|a| a.apps_enforced)
        // Skip blocks currently on a break — their apps run freely.
        .filter(|a| a.break_until_unix.is_none_or(|t| t <= now))
        .filter(|a| !a.block.apps.is_empty())
        .map(|a| (a.block.id, a.block.apps.clone()))
        .collect()
}

/// Number of PIDs in `killed` that were NOT killed on the previous tick.
/// Pure, so the per-PID dedup is unit-testable without a live `/proc`.
fn count_new_kills(killed: &HashSet<i32>, recently_killed: &HashSet<i32>) -> usize {
    killed
        .iter()
        .filter(|p| !recently_killed.contains(p))
        .count()
}

/// Scan `/proc`, SIGKILL every process matching any group's matchers, and
/// return the set of PIDs actually killed this tick (used both for dedup and
/// the kill count). ESRCH (already gone) is not counted — nothing was killed.
fn sweep(groups: &[(u64, Vec<AppMatcher>)]) -> HashSet<i32> {
    let mut killed = HashSet::new();
    let procs = match all_processes() {
        Ok(p) => p,
        Err(e) => {
            warn!(?e, "all_processes() failed");
            return killed;
        }
    };
    for proc in procs.flatten() {
        // First matching group attributes the kill; one SIGKILL is enough.
        let Some((block_id, _)) = groups.iter().find(|(_, m)| matches_any(&proc, m)) else {
            continue;
        };
        let pid = proc.pid();
        debug!(pid, block_id, "killing process");
        match kill(Pid::from_raw(pid), Signal::SIGKILL) {
            Ok(()) => {
                killed.insert(pid);
            }
            Err(nix::errno::Errno::ESRCH) => {} // already gone; nothing killed
            Err(e) => warn!(?e, pid, "SIGKILL failed"),
        }
    }
    killed
}

fn matches_any(proc: &procfs::process::Process, matchers: &[AppMatcher]) -> bool {
    let exe = proc.exe().ok();
    let cmdline = proc.cmdline().ok();
    let comm = proc.stat().ok().map(|s| s.comm);
    proc_matches(
        exe.as_deref(),
        cmdline.as_deref(),
        comm.as_deref(),
        matchers,
    )
}

/// Pure matcher over a process's identity fields, split out so it can be tested
/// without a live `/proc`. `exe` is the resolved `/proc/<pid>/exe`, `cmdline`
/// its argv, `comm` the kernel `comm` name.
fn proc_matches(
    exe: Option<&Path>,
    cmdline: Option<&[String]>,
    comm: Option<&str>,
    matchers: &[AppMatcher],
) -> bool {
    for m in matchers {
        match m {
            AppMatcher::ExePath { path } => {
                if exe == Some(Path::new(path)) {
                    return true;
                }
            }
            AppMatcher::Basename { name } => {
                if let Some(p) = exe {
                    if p.file_name().and_then(|n| n.to_str()) == Some(name.as_str()) {
                        return true;
                    }
                }
                // Fallback to the kernel comm name (e.g. for kernel-truncated
                // or wrapper processes whose exe basename differs).
                if comm == Some(name.as_str()) {
                    return true;
                }
            }
            AppMatcher::Cmdline { contains } => {
                if let Some(parts) = cmdline {
                    if parts.join(" ").contains(contains.as_str()) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

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
            apps_enforced,
            lock: LockMode::Unlocked,
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

    // ── count_new_kills(): per-PID dedup across ticks ───────────────────────

    #[test]
    fn same_pid_counts_once_new_pid_counts_again() {
        let set = |pids: &[i32]| pids.iter().copied().collect::<HashSet<i32>>();

        // Tick 1: two fresh kills, nothing seen before → both count.
        let mut recently = HashSet::new();
        let killed = set(&[10, 20]);
        assert_eq!(count_new_kills(&killed, &recently), 2);
        recently = killed;

        // Tick 2: the same PIDs still lingering → none count again.
        let killed = set(&[10, 20]);
        assert_eq!(count_new_kills(&killed, &recently), 0);
        recently = killed;

        // Tick 3: one lingering, one brand-new PID → only the new one counts.
        let killed = set(&[10, 30]);
        assert_eq!(count_new_kills(&killed, &recently), 1);
        recently = killed;

        // The PID disappears (empty tick clears it), then a reused PID with
        // the same number reappears → it counts again.
        let killed = HashSet::new();
        assert_eq!(count_new_kills(&killed, &recently), 0);
        recently = killed;
        let killed = set(&[10]);
        assert_eq!(count_new_kills(&killed, &recently), 1);
    }
}
