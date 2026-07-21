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
//! `grepfocus_doh` table), and with chattr degraded `/etc/hosts` can be
//! rewritten externally. So a memo hit isn't blindly trusted — while a domain
//! block is active, `sync` re-probes the live system at most once per
//! `REVERIFY_SECS`, verifying the two halves independently: hosts drift
//! triggers a full re-apply, while an nft-only problem (drifted table, or an
//! nft half known-broken since apply time) is healed with an nft-only
//! re-install that never rewrites `/etc/hosts`.

use std::collections::BTreeSet;

use grepfocus_core::license::features;
use grepfocus_core::{now_unix, ActiveBlock};
use tracing::{debug, info, warn};

use crate::{dns, has_feature, hosts, nftables, Daemon};

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
    // `tamper_protect` (the premium chattr +i hardening) is read at apply
    // time, alongside the union it will be applied with. It is deliberately
    // NOT part of the memo: a license change alone never forces a rewrite of
    // /etc/hosts — the immutable bit simply catches up on the next natural
    // re-apply (union change or detected drift). That next apply is a fresh
    // application of a new enforcement state, so taking the license as of
    // that moment matches the "gate at activation time" rule; mid-block the
    // bit can only be *added* this way (it is never proactively cleared for
    // license reasons — the pre-write `chattr -i` is mechanical and the
    // hosts content itself is free-tier).
    let (domains, tamper_protect) = {
        let st = daemon.state.lock().await;
        let lic = daemon.license.lock().await;
        (
            union_domains(&st.active, now),
            has_feature(lic.as_ref(), &st, features::TAMPER_PROTECTION),
        )
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
    // `applied` still holds the PREVIOUS union here — it is only replaced on
    // the success branch below — so this is the last point at which we can
    // tell a real enforcement change from a drift re-apply.
    let changed = union_changed(applied.as_ref().map(|p| p.domains.as_slice()), &domains);
    match apply(&domains, tamper_protect) {
        Ok(nft_ok) => {
            // Only after the change actually landed, and only when the set of
            // blocked domains really moved: a drift re-apply rewrites
            // /etc/hosts with an identical union, so no cached lookup can
            // have gone stale and there is nothing to flush. Best-effort and
            // infallible — see the dns module docs for what it can't fix
            // (browsers cache DNS internally for about a minute).
            if changed {
                dns::flush_caches();
            }
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

/// Whether an apply is changing *what* is enforced, rather than re-asserting
/// what already was. Decides one thing only: whether to flush the system DNS
/// cache (`dns::flush_caches`), which is worth doing exactly when a name's
/// resolution is about to change — a break starting or ending, a block
/// starting or expiring.
///
/// A drift re-apply is deliberately excluded: it rewrites `/etc/hosts` with a
/// byte-identical domain set, so no resolver answer can have gone stale and a
/// flush would be pure cost. Since the periodic probe can re-apply as often as
/// every `REVERIFY_SECS` while a block is active, treating drift as a change
/// would flush the cache of a machine that is enforcing perfectly.
///
/// No memo (`None`) counts as a change. That is the first apply after daemon
/// start or after a failed apply cleared the memo, and in neither case do we
/// know what the resolver is holding — a daemon restarted across a break
/// boundary is precisely the case where the cache is stale and nothing in
/// memory says so. The cost of being wrong is one redundant flush per daemon
/// start.
fn union_changed(previous: Option<&[String]>, next: &[String]) -> bool {
    previous.is_none_or(|prev| prev != next)
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
/// `tamper_protect` gates ONLY the trailing `chattr +i` inside
/// `hosts::apply_block` — the hosts content and the nft DoH table are
/// free-tier enforcement, the immutable bit is the premium hardening layer.
///
/// Returns whether the nft half succeeded, for the memo: a hosts failure is
/// fatal (`Err`), an nft failure is degraded-but-enforced (`Ok(false)`) so
/// the periodic probe keeps retrying the nft half.
///
/// DoH blocking only matters when websites are being blocked — an
/// app-only block (`domains: []`) doesn't need it.
fn apply(domains: &[String], tamper_protect: bool) -> anyhow::Result<bool> {
    if domains.is_empty() {
        hosts::clear_block()?;
        if let Err(e) = nftables::clear() {
            warn!(?e, "nftables clear failed (continuing)");
        }
        // Nothing is enforced, so there is no nft half to be unhealthy —
        // and `needs_probe` never fires on an empty union anyway.
        Ok(true)
    } else {
        hosts::apply_block(domains, tamper_protect)?;
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

    /// The DNS flush must fire on every real transition — block start, block
    /// expiry, break start, break end — and never on a drift re-apply, which
    /// re-writes the same union.
    #[test]
    fn union_changed_only_on_real_transitions() {
        let one = one_domain();
        let two = vec!["news.example".to_string(), "reddit.com".to_string()];
        // Drift re-apply: same union, nothing can have gone stale.
        assert!(!union_changed(Some(&one), &one));
        assert!(!union_changed(Some(&[]), &[]));
        // Block start / break end (empty -> blocked) and the reverse.
        assert!(union_changed(Some(&[]), &one));
        assert!(union_changed(Some(&one), &[]));
        // One of several blocks going on break, and coming back.
        assert!(union_changed(Some(&two), &one));
        assert!(union_changed(Some(&one), &two));
        // No memo: daemon start, or a retry after a failed apply — we can't
        // know what the resolver cached, so flush.
        assert!(union_changed(None, &one));
        assert!(union_changed(None, &[]));
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
