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
//!
//! This module also owns the lifetime of the loopback proxy (`listener`),
//! because the proxy and the sink IP written into `/etc/hosts` are one
//! decision: the sink points at `127.0.0.1` only while both loopback ports are
//! actually held (see `sink_ip`). The proxy is a THIRD half in the
//! degradation policy's sense, and the weakest one — a hosts failure is fatal,
//! an nft failure is degraded-but-enforced, and a failed bind costs nothing
//! but the instant-refusal, since the sink simply stays `0.0.0.0` and blocking
//! is untouched.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use grepfocus_core::license::features;
use grepfocus_core::{now_unix, ActiveBlock};
use tracing::{debug, info, warn};

use crate::listener::ProxyListener;
use crate::{dns, has_feature, hosts, nftables, Daemon};

/// How long a live-system verification stays fresh. While a domain block is
/// active, a memo-hit `sync` older than this re-probes the nft table and the
/// hosts marker (one `nft` exec + one file read) — cheap enough for the 1s
/// scheduler tick because it runs at most once per interval.
const REVERIFY_SECS: u64 = 30;

/// The memoized result of the last successful `apply`: which domain union is
/// live, at which sink IP, and when the live system was last confirmed to
/// still match it.
pub struct Applied {
    domains: Vec<String>,
    /// The sink IP the domains above were pointed at.
    ///
    /// Part of the memo, and deliberately unlike `tamper_protect`, which is
    /// read at apply time and excluded from it (see `sync`). What separates
    /// them is what each one changes. `tamper_protect` decides whether a
    /// `chattr +i` runs AFTER the write, so skipping a re-apply leaves nothing
    /// stale *in the file* and the immutable bit catches up at the next
    /// natural one. The sink IP is IN the file — it is the address on every
    /// line of the managed region. Leave it out of the memo and toggling
    /// `instant_breaks` while a block is already active hits the memo and
    /// changes nothing: the proxy starts listening on `127.0.0.1` while every
    /// blocked name still resolves to `0.0.0.0`, and stays that way until the
    /// block ends. Comparing it alongside `domains` turns that toggle into an
    /// ordinary re-apply.
    sink: Ipv4Addr,
    verified_at: u64,
    /// Whether the nftables half actually installed at the last apply. The
    /// hosts half is fatal-on-failure, so its success is implied by the memo
    /// existing at all.
    nft_ok: bool,
}

impl Applied {
    /// Whether the live system this memo describes is already what a fresh
    /// apply would write. Both halves of the file's identity are compared:
    /// which names are blocked, and the address they point at.
    fn matches(&self, domains: &[String], sink: Ipv4Addr) -> bool {
        self.domains == domains && self.sink == sink
    }
}

/// Reconcile the live system (`/etc/hosts` + nftables) with the current
/// `state.active`. This is the only enforcement entry point callers should
/// use after mutating state:
///
/// - All applies are serialized by `daemon.applied`, and the domain union is
///   computed *inside* that critical section, so a stale union can never be
///   applied after a fresher one.
/// - The last successful apply is memoized — the union AND the sink IP it was
///   written with; a match on both is a cheap no-op, which lets the scheduler
///   call this every tick, while a changed sink re-applies. While a
///   domain block is active, though, a memo hit that hasn't been verified in
///   `REVERIFY_SECS` re-probes the two halves independently: a missing hosts
///   marker means a full re-apply (catching external `/etc/hosts` rewrites),
///   while a drifted nft table (firewall reload) or an nft half known-broken
///   since apply time gets an nft-only re-install — `/etc/hosts` is never
///   rewritten for an nft-only problem.
/// - On failure the memo is cleared, so the next tick retries automatically.
/// - The loopback proxy is started and released here too, since the sink IP
///   written into `/etc/hosts` depends on whether it is listening.
///
/// Callers must NOT hold the state lock (lock order is `applied` → `state`;
/// `daemon.listener` is taken only inside this function, with `applied`
/// already held and the state lock already dropped, so the order extends to
/// `applied` → `listener` and nothing else can reach that mutex at all).
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
    //
    // `instant_breaks` is read in the same breath, but it is NOT the same kind
    // of input: it decides the sink IP, which is file content, so it belongs
    // to the memo. See `Applied::sink` for the contrast. `any_block_active` is
    // captured under the same lock because the proxy must stay bound whenever a
    // block is active — even a solo break that empties the written union — and
    // that is a fact about `state.active`, not about `domains`.
    let (domains, tamper_protect, instant_breaks, any_block_active) = {
        let st = daemon.state.lock().await;
        let lic = daemon.license.lock().await;
        (
            union_domains(&st.active, now),
            has_feature(lic.as_ref(), &st, features::TAMPER_PROTECTION),
            st.settings.instant_breaks,
            !st.active.is_empty(),
        )
    };
    // Settle the proxy BEFORE anything is written: `/etc/hosts` must never
    // point a blocked name at a loopback port we have not bound yet. The proxy
    // is wanted whenever a block is active and `instant_breaks` is on —
    // deliberately keyed on `state.active`, NOT on whether the written union is
    // non-empty, because a solo break empties the union exactly when the proxy
    // must stay up to refuse the domains that are about to come back. The state
    // lock is already released here and `applied` is still held, which is the
    // lock order this mutex lives under.
    let sink = sink_ip(ensure_detection(daemon, instant_breaks && any_block_active).await);
    if let Some(prev) = applied.as_mut() {
        if prev.matches(&domains, sink) {
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
    // tell a real enforcement change from a drift re-apply. Note the sink
    // passed to `apply` is the one just decided, never the memoized one: a
    // drift re-apply must rewrite the file with today's address.
    let changed = resolution_changed(
        applied.as_ref().map(|p| (p.domains.as_slice(), p.sink)),
        &domains,
        sink,
    );
    match apply(&domains, sink, tamper_protect) {
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
                sink,
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
/// The sink IP counts as much as the domain set does, because a resolver
/// answer is the pair: the same names answering `127.0.0.1` instead of
/// `0.0.0.0` is exactly a changed resolution, and a cache still holding the
/// old address is what would leave a freshly enabled proxy seeing nothing.
///
/// A drift re-apply is deliberately excluded: it rewrites `/etc/hosts` with a
/// byte-identical region, so no resolver answer can have gone stale and a
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
fn resolution_changed(
    previous: Option<(&[String], Ipv4Addr)>,
    next_domains: &[String],
    next_sink: Ipv4Addr,
) -> bool {
    previous.is_none_or(|(domains, sink)| domains != next_domains || sink != next_sink)
}

/// What the loopback proxy is actually doing right now. Split out as data so
/// the sink-IP decision below is a pure function — the shape
/// `hosts::hardening_for` uses for the license gate, and for the same reason:
/// the side effect (binding privileged ports) is untestable, the decision must
/// not be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Detection {
    /// No proxy running: `instant_breaks` is off, or nothing is blocked.
    Off,
    /// Both loopback ports held — a blocked connection is refused by us.
    Listening,
    /// The proxy was wanted, but at least one port could not be bound.
    Degraded,
}

/// Which address the blocked names are pointed at in `/etc/hosts`.
///
/// `127.0.0.1` only while the proxy holds BOTH loopback ports. Every other
/// case keeps the historical `0.0.0.0`, the degraded one included — and that
/// asymmetry is the whole point of `fully_bound`: a port we failed to bind is
/// owned by some other process, and pointing a blocked domain at a loopback
/// port owned by a stranger would hand it the browser's request instead of
/// failing it.
///
/// Either address enforces, which is why a bind failure is never an
/// enforcement failure. Nothing answers on `0.0.0.0`; `127.0.0.1` with our
/// socket bound is answered by the proxy, which reads the hostname and refuses
/// the connection, and with nothing bound at all is refused outright
/// (`ECONNREFUSED`). In no case does the browser reach the site. The choice
/// decides only whether the connection dies on a socket we own.
fn sink_ip(detection: Detection) -> Ipv4Addr {
    match detection {
        Detection::Listening => Ipv4Addr::LOCALHOST,
        Detection::Off | Detection::Degraded => Ipv4Addr::UNSPECIFIED,
    }
}

/// Bring the loopback proxy into the state `want` describes, and report what
/// it is really doing so `sink_ip` can decide the address.
///
/// The ports are held for exactly as long as they can be useful: started when
/// a block is live and `instant_breaks` is on, released the moment either
/// stops being true. `ProxyListener::release` consumes the listener, which is
/// why the slot is an `Option` and teardown is a `take`.
///
/// A start that could not bind both ports is NOT retried on the next tick.
/// `sync` runs every second, and a per-tick re-bind would re-log the failure
/// forever — the same trap the nft re-probe sidesteps with a `debug!`, except
/// here it would also mean hammering a port some other process legitimately
/// owns. The retry comes at the next natural transition instead: a block
/// starting, or the user toggling the setting. For the same reason a
/// half-bound listener is kept in the slot rather than dropped — an empty slot
/// is precisely what triggers a re-bind — and keeping it now costs nothing at
/// all: `ProxyListener::start` binds both ports or neither, so a listener that
/// reports itself not fully bound is holding no socket to keep.
async fn ensure_detection(daemon: &Daemon, want: bool) -> Detection {
    let mut slot = daemon.listener.lock().await;
    if !want {
        if let Some(running) = slot.take() {
            // Awaited, not fired and forgotten: `release` does not return until
            // the ports are actually bindable, so the next block to start can
            // re-bind them on the very next tick instead of losing the proxy to
            // an `EADDRINUSE` against the socket we just gave up.
            running.release().await;
        }
        return Detection::Off;
    }
    if slot.is_none() {
        let started = ProxyListener::start().await;
        if !started.fully_bound() {
            // Once, at the transition. The instant-refusal is the only
            // casualty: the sink stays 0.0.0.0 and every blocked name still
            // fails to connect, exactly as it did before this feature existed.
            warn!(
                "loopback proxy could not bind both ports — blocked domains fall back \
                 to 0.0.0.0; blocking is unaffected"
            );
        }
        *slot = Some(started);
    }
    match slot.as_ref() {
        Some(running) if running.fully_bound() => Detection::Listening,
        _ => Detection::Degraded,
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
/// `sink` is the address every blocked name is written with, from `sink_ip`.
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
fn apply(domains: &[String], sink: Ipv4Addr, tamper_protect: bool) -> anyhow::Result<bool> {
    if domains.is_empty() {
        hosts::clear_block()?;
        if let Err(e) = nftables::clear() {
            warn!(?e, "nftables clear failed (continuing)");
        }
        // Nothing is enforced, so there is no nft half to be unhealthy —
        // and `needs_probe` never fires on an empty union anyway.
        Ok(true)
    } else {
        hosts::apply_block(domains, sink, tamper_protect)?;
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

    const DARK: Ipv4Addr = Ipv4Addr::UNSPECIFIED; // 0.0.0.0
    const SEEN: Ipv4Addr = Ipv4Addr::LOCALHOST; // 127.0.0.1

    /// The DNS flush must fire on every real transition — block start, block
    /// expiry, break start, break end — and never on a drift re-apply, which
    /// re-writes the same region.
    #[test]
    fn resolution_changed_only_on_real_transitions() {
        let one = one_domain();
        let two = vec!["news.example".to_string(), "reddit.com".to_string()];
        // Drift re-apply: same union at the same sink, nothing can have gone
        // stale.
        assert!(!resolution_changed(Some((&one, DARK)), &one, DARK));
        assert!(!resolution_changed(Some((&[], DARK)), &[], DARK));
        // Block start / break end (empty -> blocked) and the reverse.
        assert!(resolution_changed(Some((&[], DARK)), &one, DARK));
        assert!(resolution_changed(Some((&one, DARK)), &[], DARK));
        // One of several blocks going on break, and coming back.
        assert!(resolution_changed(Some((&two, DARK)), &one, DARK));
        assert!(resolution_changed(Some((&one, DARK)), &two, DARK));
        // Same names, new address: the resolver's cached answer is now wrong,
        // which is what would leave a just-enabled proxy seeing nothing.
        assert!(resolution_changed(Some((&one, DARK)), &one, SEEN));
        assert!(resolution_changed(Some((&one, SEEN)), &one, DARK));
        // No memo: daemon start, or a retry after a failed apply — we can't
        // know what the resolver cached, so flush.
        assert!(resolution_changed(None, &one, DARK));
        assert!(resolution_changed(None, &[], DARK));
    }

    /// The sink is loopback only when the proxy really holds both ports. A
    /// degraded proxy must read exactly like a switched-off one: some other
    /// process owns that port, and pointing a blocked name at it would hand it
    /// the request.
    #[test]
    fn sink_is_loopback_only_while_fully_listening() {
        assert_eq!(sink_ip(Detection::Off), DARK);
        assert_eq!(sink_ip(Detection::Listening), SEEN);
        assert_eq!(sink_ip(Detection::Degraded), DARK);
    }

    /// Toggling `instant_breaks` mid-block changes the file's content, so it
    /// must miss the memo and force a re-apply — otherwise `/etc/hosts` keeps
    /// pointing at the old address for the rest of the block. (Contrast
    /// `tamper_protect`, which is excluded from the memo precisely because it
    /// leaves nothing stale in the file.)
    #[test]
    fn memo_misses_when_only_the_sink_changes() {
        let memo = Applied {
            domains: one_domain(),
            sink: DARK,
            verified_at: 0,
            nft_ok: true,
        };
        assert!(memo.matches(&one_domain(), DARK));
        assert!(!memo.matches(&one_domain(), SEEN));
        // And the domain half still decides on its own.
        assert!(!memo.matches(&[], DARK));
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
