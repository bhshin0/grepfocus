//! frostbited — privileged blocking daemon.
//!
//! Runs as root via systemd. Owns the persisted block state, edits
//! /etc/hosts (with chattr +i during active blocks), and SIGKILLs blocked
//! processes. Talks to the GUI over a Unix socket at /run/frostbite/sock.

use std::sync::Arc;

use anyhow::Context;
use tokio::sync::Mutex;
use tracing::{error, info};

mod hosts;
mod ipc;
mod paths;
mod procwatch;
mod scheduler;
mod state;

use frostbite_core::State;

/// Runtime context shared across all daemon tasks.
pub struct Daemon {
    /// Persisted state — blocks list and the currently active block, if any.
    pub state: Mutex<State>,
    /// HMAC key loaded from /etc/frostbite/secret at startup.
    pub key: Vec<u8>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    if !nix::unistd::Uid::effective().is_root() {
        anyhow::bail!("frostbited must run as root");
    }

    paths::ensure_dirs().context("creating runtime/state directories")?;
    let key = state::load_or_create_secret().context("loading HMAC secret")?;

    let initial = state::load(&key).unwrap_or_else(|err| {
        error!(?err, "state file invalid or missing — starting fresh and clearing any leftover hosts block");
        if let Err(e) = hosts::clear_block() {
            error!(?e, "failed to clear leftover hosts block");
        }
        State::default()
    });

    info!(
        block_count = initial.blocks.len(),
        active = initial.active.is_some(),
        "daemon starting"
    );

    let daemon = Arc::new(Daemon {
        state: Mutex::new(initial),
        key,
    });

    // If we're starting up with an active block, re-apply its enforcement.
    {
        let st = daemon.state.lock().await;
        if let Some(active) = &st.active {
            if active.ends_at_unix > frostbite_core::now_unix() {
                info!("re-applying active block on startup");
                let domains: Vec<String> = active.block.domains.clone();
                drop(st);
                if let Err(e) = hosts::apply_block(&domains) {
                    error!(?e, "failed to re-apply hosts block");
                }
            }
        }
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
