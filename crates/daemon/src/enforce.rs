//! Helpers shared by ipc.rs and scheduler.rs for reconciling the live system
//! state (the `/etc/hosts` file + nftables DoH block) with the in-memory
//! `state.active` list.
//!
//! The pattern across callers is always: hold the state lock just long enough
//! to mutate and compute the union of blocked domains, drop the lock, then
//! call `apply` outside the lock so slow filesystem / nft IO never blocks
//! the IPC server or the procwatch loop.

use std::collections::BTreeSet;

use frostbite_core::{now_unix, ActiveBlock};
use tracing::warn;

use crate::{hosts, nftables, Daemon};

/// Reconcile the live system (`/etc/hosts` + nftables) with the current
/// `state.active`. This is the only enforcement entry point callers should
/// use after mutating state:
///
/// - All applies are serialized by `daemon.applied`, and the domain union is
///   computed *inside* that critical section, so a stale union can never be
///   applied after a fresher one.
/// - The last successfully applied union is memoized; matching unions are a
///   cheap no-op, which lets the scheduler call this every tick.
/// - On failure the memo is cleared, so the next tick retries automatically.
///
/// Callers must NOT hold the state lock (lock order is `applied` → `state`).
pub async fn sync(daemon: &Daemon) -> anyhow::Result<()> {
    let mut applied = daemon.applied.lock().await;
    let domains = {
        let st = daemon.state.lock().await;
        union_domains(&st.active, now_unix())
    };
    if applied.as_ref() == Some(&domains) {
        return Ok(());
    }
    match apply(&domains) {
        Ok(()) => {
            *applied = Some(domains);
            Ok(())
        }
        Err(e) => {
            *applied = None;
            Err(e)
        }
    }
}

/// Deduplicated, sorted union of all domains across the active blocks that are
/// currently being enforced. Blocks on a break (`break_until_unix > now`) are
/// skipped so their domains resolve again until the break ends.
fn union_domains(active: &[ActiveBlock], now: u64) -> Vec<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    for a in active {
        if a.break_until_unix.is_some_and(|t| t > now) {
            continue;
        }
        for d in &a.block.domains {
            let d = d.trim();
            if !d.is_empty() {
                set.insert(d.to_string());
            }
        }
    }
    set.into_iter().collect()
}

/// Apply a freshly computed union to `/etc/hosts` AND the nftables DoH
/// block table. If empty, clears both; otherwise installs both.
///
/// DoH blocking only matters when websites are being blocked — an
/// app-only block (`domains: []`) doesn't need it.
fn apply(domains: &[String]) -> anyhow::Result<()> {
    if domains.is_empty() {
        hosts::clear_block()?;
        if let Err(e) = nftables::clear() {
            warn!(?e, "nftables clear failed (continuing)");
        }
    } else {
        hosts::apply_block(domains)?;
        if let Err(e) = nftables::apply() {
            // Hosts block is in place; DoH bypass is open. Log loudly but
            // don't unwind — partial enforcement is better than none.
            warn!(?e, "nftables apply failed — Firefox DoH bypass not closed");
        }
    }
    Ok(())
}
