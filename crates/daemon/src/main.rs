//! frostbited — privileged blocking daemon.
//!
//! Runs as root via systemd. Owns the persisted block state, edits
//! /etc/hosts (with chattr +i during active blocks), and SIGKILLs blocked
//! processes. Talks to the GUI over a Unix socket at /run/frostbite/sock.
//!
//! Also ships the offline recovery path: `frostbited cleanup` tears down all
//! enforcement without needing a working daemon (see `cleanup`).

use std::sync::Arc;

use anyhow::Context;
use tokio::sync::Mutex;
use tracing::{error, info};

mod auth;
mod cleanup;
mod enforce;
mod hosts;
mod ipc;
mod nftables;
mod paths;
mod procwatch;
mod scheduler;
mod state;

use frostbite_core::{now_unix, State};

/// Runtime context shared across all daemon tasks.
pub struct Daemon {
    /// Persisted state — blocks, active blocks, schedules.
    pub state: Mutex<State>,
    /// HMAC key loaded from /etc/frostbite/secret at startup.
    pub key: Vec<u8>,
    /// Unix time until which configuration changes are unlocked. In-memory
    /// only: a daemon restart relocks the settings. `0` means locked.
    pub unlocked_until: Mutex<u64>,
    /// Serializes enforcement writes and memoizes the domain union that was
    /// last applied successfully, plus when it was last verified live.
    /// `None` means unknown/dirty — the next `enforce::sync` re-applies
    /// unconditionally. See `enforce::sync`.
    pub applied: Mutex<Option<enforce::Applied>>,
}

fn main() -> anyhow::Result<()> {
    // Initialize tracing before dispatching so subcommands log too.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => run_daemon(),
        Some("cleanup") => {
            let mut opts = cleanup::Opts {
                purge: false,
                force: false,
            };
            for arg in args {
                match arg.as_str() {
                    "--purge" => opts.purge = true,
                    "--force" => opts.force = true,
                    other => usage(&format!("unknown cleanup flag: {}", other)),
                }
            }
            cleanup::run(opts)
        }
        Some(other) => usage(&format!("unknown subcommand: {}", other)),
    }
}

/// Print an error plus usage to stderr and exit nonzero.
fn usage(err: &str) -> ! {
    eprintln!("error: {}", err);
    eprintln!(
        "usage: frostbited                        run the daemon (root; normally via systemd)"
    );
    eprintln!("       frostbited cleanup [--force] [--purge]");
    eprintln!(
        "                                          tear down all enforcement (daemon stopped)"
    );
    eprintln!("         --force  skip the running-daemon check");
    eprintln!("         --purge  also delete /var/lib/frostbite and /etc/frostbite");
    std::process::exit(2);
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn run_daemon() -> anyhow::Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        anyhow::bail!("frostbited must run as root");
    }

    paths::ensure_dirs().context("creating runtime/state directories")?;
    let key = state::load_or_create_secret().context("loading HMAC secret")?;

    let mut initial = match state::load(&key) {
        Ok(s) => s,
        Err(err) => {
            let missing = err.chain().any(|e| {
                e.downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
            });
            if missing {
                info!("no state file yet — first run, starting fresh");
            } else {
                error!(
                    ?err,
                    "state file corrupted — starting fresh and clearing any leftover hosts block"
                );
                if let Err(e) = hosts::clear_block() {
                    error!(?e, "failed to clear leftover hosts block");
                }
            }
            State::default()
        }
    };

    // Drop any active blocks that have already expired between shutdown and
    // startup. (They will simply never be re-applied.)
    let now = now_unix();
    let before = initial.active.len();
    initial.active.retain(|a| a.ends_at_unix > now);
    let dropped = before - initial.active.len();
    if dropped > 0 {
        info!(dropped, "discarded expired active blocks on startup");
    }
    if dropped > 0 {
        if let Err(e) = state::save(&initial, &key) {
            error!(?e, "failed to save state after dropping expired actives");
        }
    }

    info!(
        block_count = initial.blocks.len(),
        active_count = initial.active.len(),
        schedule_count = initial.schedules.len(),
        "daemon starting"
    );

    let daemon = Arc::new(Daemon {
        state: Mutex::new(initial),
        key,
        unlocked_until: Mutex::new(0),
        applied: Mutex::new(None),
    });

    // Re-apply the union of all still-active blocks before accepting clients.
    if let Err(e) = enforce::sync(&daemon).await {
        error!(?e, "failed to re-apply hosts enforcement on startup");
    }

    let ipc_handle = tokio::spawn(ipc::serve(daemon.clone()));
    let watch_handle = tokio::spawn(procwatch::run(daemon.clone()));
    let sched_handle = tokio::spawn(scheduler::run(daemon.clone()));

    // Run until any task fails or we receive SIGTERM/SIGINT.
    tokio::select! {
        r = ipc_handle => { error!(?r, "ipc task exited"); }
        r = watch_handle => { error!(?r, "procwatch task exited"); }
        r = sched_handle => { error!(?r, "scheduler task exited"); }
        _ = tokio::signal::ctrl_c() => { info!("received SIGINT, shutting down"); }
    }

    Ok(())
}
