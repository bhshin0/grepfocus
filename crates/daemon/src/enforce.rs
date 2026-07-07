//! Helpers shared by ipc.rs and scheduler.rs for reconciling the live system
//! state (the `/etc/hosts` file + nftables DoH block) with the in-memory
//! `state.active` list.
//!
//! The pattern across callers is always: hold the state lock just long enough
//! to mutate and compute the union of blocked domains, drop the lock, then
//! call `apply` outside the lock so slow filesystem / nft IO never blocks
//! the IPC server or the procwatch loop.
//!
//! Enforcement can also drift underneath us without the domain union ever
//! changing: a firewalld/ufw reload flushes the ruleset (wiping the
//! `frostbite_doh` table), and with chattr degraded `/etc/hosts` can be
//! rewritten externally. So a memo hit isn't blindly trusted — while a domain
//! block is active, `sync` re-probes the live system at most once per
//! `REVERIFY_SECS`, verifying the two halves independently: hosts drift
//! triggers a full re-apply, while an nft-only problem (drifted table, or an
//! nft half known-broken since apply time) is healed with an nft-only
//! re-install that never rewrites `/etc/hosts`.

use std::collections::BTreeSet;

use frostbite_core::{now_unix, ActiveBlock};
use tracing::{debug, info, warn};

use crate::{hosts, nftables, Daemon};

/// How long a live-system verification stays fresh. While a domain block is
/// active, a memo-hit `sync` older than this re-probes the nft table and the
/// hosts marker (one `nft` exec + one file read) — cheap enough for the 1s
/// scheduler tick because it runs at most once per interval.
const REVERIFY_SECS: u64 = 30;

/// The memoized result of the last successful `apply`: which domain union is
/// live, and when the live system was last confirmed to still match it.
pub struct Applied {
    domains: Vec<String>,
    verified_at: u64,
    /// Whether the nftables half actually installed at the last apply. The
    /// hosts half is fatal-on-failure, so its success is implied by the memo
    /// existing at all.
    nft_ok: bool,
}

/// Reconcile the live system (`/etc/hosts` + nftables) with the current
/// `state.active`. This is the only enforcement entry point callers should
/// use after mutating state:
///
/// - All applies are serialized by `daemon.applied`, and the domain union is
///   computed *inside* that critical section, so a stale union can never be
///   applied after a fresher one.
/// - The last successfully applied union is memoized; matching unions are a
///   cheap no-op, which lets the scheduler call this every tick. While a
///   domain block is active, though, a memo hit that hasn't been verified in
///   `REVERIFY_SECS` re-probes the two halves independently: a missing hosts
///   marker means a full re-apply (catching external `/etc/hosts` rewrites),
///   while a drifted nft table (firewall reload) or an nft half known-broken
///   since apply time gets an nft-only re-install — `/etc/hosts` is never
///   rewritten for an nft-only problem.
/// - On failure the memo is cleared, so the next tick retries automatically.
///
/// Callers must NOT hold the state lock (lock order is `applied` → `state`).
pub async fn sync(daemon: &Daemon) -> anyhow::Result<()> {
    let mut applied = daemon.applied.lock().await;
    let now = now_unix();
    let domains = {
        let st = daemon.state.lock().await;
        union_domains(&st.active, now)
    };
    if let Some(prev) = applied.as_mut() {
        if prev.domains == domains {
            if !needs_probe(&domains, prev.verified_at, now) {
                return Ok(());
            }
            if hosts::block_present() {
                // Hosts half intact — verify/heal the nft half alone, never
                // rewriting /etc/hosts for an nft-only problem.
                if prev.nft_ok && nftables::table_exists() {
                    prev.verified_at = now;
                    return Ok(());
                }
                if prev.nft_ok {
                    warn!("nftables DoH table drifted (firewall reload?) — re-installing");
                }
                match nftables::apply() {
                    Ok(()) => {
                        if !prev.nft_ok {
                            info!("nftables DoH table installed after earlier failure");
                        }
                        prev.nft_ok = true;
                    }
                    // Not warn: on a host without a working nft this fires
                    // every REVERIFY_SECS forever; the transition was already
                    // warned at apply time.
                    Err(e) => {
                        debug!(?e, "nftables still unavailable — will retry");
                        prev.nft_ok = false;
                    }
                }
                prev.verified_at = now;
                return Ok(());
            }
            warn!("enforcement drift detected — re-applying");
        }
    }
    match apply(&domains) {
        Ok(nft_ok) => {
            *applied = Some(Applied {
                domains,
                verified_at: now,
                nft_ok,
            });
            Ok(())
        }
        Err(e) => {
            *applied = None;
            Err(e)
        }
    }
}

/// Whether a memo-hit `sync` should probe the live system for drift. Never
/// probes while nothing is enforced (empty union — there is nothing to
/// verify) or while the last verification is younger than `REVERIFY_SECS`.
///
/// `verified_at` comes from the wall clock, so the comparison uses
/// `abs_diff`: a backward step after stamping would leave `verified_at` in
/// the future, and a one-sided subtraction would suppress probing for the
/// full magnitude of the step. Instead, any divergence ≥ `REVERIFY_SECS` in
/// either direction triggers a probe, and the probe re-stamps `verified_at`,
/// so a stepped clock self-corrects within one interval.
fn needs_probe(domains: &[String], verified_at: u64, now: u64) -> bool {
    !domains.is_empty() && now.abs_diff(verified_at) >= REVERIFY_SECS
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
/// Returns whether the nft half succeeded, for the memo: a hosts failure is
/// fatal (`Err`), an nft failure is degraded-but-enforced (`Ok(false)`) so
/// the periodic probe keeps retrying the nft half.
///
/// DoH blocking only matters when websites are being blocked — an
/// app-only block (`domains: []`) doesn't need it.
fn apply(domains: &[String]) -> anyhow::Result<bool> {
    if domains.is_empty() {
        hosts::clear_block()?;
        if let Err(e) = nftables::clear() {
            warn!(?e, "nftables clear failed (continuing)");
        }
        // Nothing is enforced, so there is no nft half to be unhealthy —
        // and `needs_probe` never fires on an empty union anyway.
        Ok(true)
    } else {
        hosts::apply_block(domains)?;
        if let Err(e) = nftables::apply() {
            // Hosts block is in place; DoH bypass is open. Log loudly but
            // don't unwind — partial enforcement is better than none.
            warn!(?e, "nftables apply failed — Firefox DoH bypass not closed");
            return Ok(false);
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_domain() -> Vec<String> {
        vec!["reddit.com".to_string()]
    }

    #[test]
    fn fresh_verification_skips_probe() {
        assert!(!needs_probe(&one_domain(), 100, 100));
        assert!(!needs_probe(&one_domain(), 100, 100 + REVERIFY_SECS - 1));
    }

    #[test]
    fn stale_verification_probes() {
        assert!(needs_probe(&one_domain(), 100, 100 + REVERIFY_SECS));
        assert!(needs_probe(&one_domain(), 100, u64::MAX));
    }

    #[test]
    fn empty_union_never_probes() {
        // Nothing enforced, nothing to verify — even arbitrarily stale.
        assert!(!needs_probe(&[], 0, u64::MAX));
    }

    #[test]
    fn clock_steps_probe_within_one_interval() {
        // A small backward step (< REVERIFY_SECS) still counts as fresh —
        // no probing every tick over minor clock adjustments.
        assert!(!needs_probe(&one_domain(), 100, 90));
        // A large backward step leaves verified_at far in the future; the
        // abs_diff comparison probes instead of waiting for `now` to catch
        // up (which could take the full magnitude of the step).
        assert!(needs_probe(&one_domain(), 10_000, 100));
    }
}
