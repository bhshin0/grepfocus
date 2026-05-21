//! Periodic /proc scan that SIGKILLs processes matching any active block.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use frostbite_core::AppMatcher;
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
            st.active
                .iter()
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
    for m in matchers {
        match m {
            AppMatcher::ExePath { path } => {
                if exe.as_deref() == Some(Path::new(path)) {
                    return true;
                }
            }
            AppMatcher::Basename { name } => {
                if let Some(p) = exe.as_deref() {
                    if p.file_name().and_then(|n| n.to_str()) == Some(name.as_str()) {
                        return true;
                    }
                }
                if let Some(c) = &comm {
                    if c == name {
                        return true;
                    }
                }
            }
            AppMatcher::Cmdline { contains } => {
                if let Some(parts) = &cmdline {
                    let joined = parts.join(" ");
                    if joined.contains(contains.as_str()) {
                        return true;
                    }
                }
            }
        }
    }
    false
}
