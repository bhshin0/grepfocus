//! Helpers shared by ipc.rs and scheduler.rs for reconciling the live system
//! state (the `/etc/hosts` file) with the in-memory `state.active` list.
//!
//! The pattern across callers is always: hold the state lock just long enough
//! to mutate and compute the union of blocked domains, drop the lock, then
//! call `apply` outside the lock so slow filesystem IO never blocks the IPC
//! server or the procwatch loop.

use std::collections::BTreeSet;

use frostbite_core::ActiveBlock;

use crate::hosts;

/// Deduplicated, sorted union of all domains across the active blocks.
pub fn union_domains(active: &[ActiveBlock]) -> Vec<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    for a in active {
        for d in &a.block.domains {
            let d = d.trim();
            if !d.is_empty() {
                set.insert(d.to_string());
            }
        }
    }
    set.into_iter().collect()
}

/// Apply a freshly computed union to `/etc/hosts`. If empty, clears the
/// managed region and removes the immutable bit; otherwise rewrites the
/// region and re-applies `chattr +i`.
pub fn apply(domains: &[String]) -> anyhow::Result<()> {
    if domains.is_empty() {
        hosts::clear_block()
    } else {
        hosts::apply_block(domains)
    }
}
