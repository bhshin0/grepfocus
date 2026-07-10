//! Periodic /proc scan that SIGKILLs processes matching any active block.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use grepfocus_core::{now_unix, AppMatcher};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use procfs::process::all_processes;
use tracing::{debug, warn};

use crate::Daemon;

const POLL_INTERVAL: Duration = Duration::from_millis(500);

pub async fn run(daemon: Arc<Daemon>) {
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let matchers: Vec<AppMatcher> = {
            let st = daemon.state.lock().await;
            if st.active.is_empty() {
                continue;
            }
            let now = now_unix();
            st.active
                .iter()
                // Skip blocks currently on a break — their apps run freely.
                .filter(|a| a.break_until_unix.is_none_or(|t| t <= now))
                .flat_map(|a| a.block.apps.iter().cloned())
                .collect()
        };
        if matchers.is_empty() {
            continue;
        }
        // /proc scanning is sync; do it on a blocking thread so we don't
        // stall the runtime.
        let _ = tokio::task::spawn_blocking(move || sweep(&matchers)).await;
    }
}

fn sweep(matchers: &[AppMatcher]) {
    let procs = match all_processes() {
        Ok(p) => p,
        Err(e) => {
            warn!(?e, "all_processes() failed");
            return;
        }
    };
    for proc in procs.flatten() {
        if matches_any(&proc, matchers) {
            let pid = proc.pid();
            debug!(pid, "killing process");
            if let Err(e) = kill(Pid::from_raw(pid), Signal::SIGKILL) {
                if e != nix::errno::Errno::ESRCH {
                    warn!(?e, pid, "SIGKILL failed");
                }
            }
        }
    }
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
}
