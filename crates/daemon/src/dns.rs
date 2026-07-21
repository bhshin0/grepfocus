//! Best-effort system DNS cache flush, run when the enforced domain union
//! changes.
//!
//! A block points its domains at `0.0.0.0` in `/etc/hosts`
//! (`hosts::render_block`); lifting the block deletes those lines. But a
//! resolver that already answered a lookup from them can keep serving that
//! same answer out of its own cache afterwards, so a site can stay broken for
//! a while after a break has started — time the user has already paid for out
//! of their allowance. Asking the system resolver to drop its cache at the
//! moment enforcement changes cuts that tail.
//!
//! What this does NOT fix — worth stating plainly, because the residual delay
//! is visible to users and this is not a complete cure:
//!
//! - **Only the system resolver, and only systemd's.** `resolvectl
//!   flush-caches` talks to systemd-resolved. An `nscd`, `dnsmasq`,
//!   `unbound` or router-level cache in front of the machine is untouched;
//!   on a system without systemd-resolved this does nothing at all.
//! - **Browsers keep their own in-process DNS cache** that no external
//!   process can reach — Chrome and Firefox both hold entries for roughly a
//!   minute. So a tab may still need a reload for up to about that long after
//!   a break starts, flush or no flush.
//!
//! It is still worth doing: a system-level cache follows record TTLs and can
//! hold onto an answer far longer than a browser's fixed ~minute, so the
//! flush turns an open-ended wait into a short, bounded one.
//!
//! Failure policy: nothing here can fail in a way the caller sees. A missing
//! `resolvectl`, a machine not running systemd-resolved, or a non-zero exit
//! all leave enforcement exactly as it was — the block or unblock has already
//! landed in `/etc/hosts` by the time we get here, and a stale cache is a
//! latency problem, never a correctness one. Hence no `Result`: there is no
//! decision for a caller to make.

use std::process::{Command, Stdio};

use tracing::debug;

/// coreutils `timeout` — same "coreutils is always installed" assumption
/// `nftables.rs` and `hosts.rs` already make.
const TIMEOUT_BIN: &str = "/usr/bin/timeout";
const RESOLVECTL: &str = "/usr/bin/resolvectl";
/// Wall-clock bound for the flush, in seconds. This runs synchronously under
/// the daemon's `applied` mutex (see `enforce::sync`), so a resolver wedged on
/// an unreachable upstream must not be able to hold the scheduler tick and
/// every Start/Break IPC behind it. Short on purpose: unlike `nft`, there is
/// nothing to lose by giving up — the flush is optional.
const FLUSH_TIMEOUT_SECS: &str = "5";

/// Ask systemd-resolved to drop its DNS cache. Best-effort and infallible by
/// construction: every outcome is logged at debug and discarded.
///
/// Bounded by coreutils `timeout` (SIGTERM at `FLUSH_TIMEOUT_SECS`, SIGKILL
/// 2s later), exactly as `nftables::nft_command` bounds `nft`; a timed-out run
/// exits 124 and reads as a plain failure here.
///
/// Everything below debug rather than warn: on a machine without
/// systemd-resolved this path is hit on *every* enforcement change forever,
/// and a permanent, unactionable warning on a normal configuration is noise
/// that trains the reader to ignore the log (same reasoning as the `debug!`
/// for a persistently unavailable `nft` in `enforce::sync`).
///
/// The exec itself is not unit-testable — it needs a live system bus and a
/// running resolver — so it is deliberately kept to a straight-line call with
/// no logic to test.
pub fn flush_caches() {
    let status = Command::new(TIMEOUT_BIN)
        .arg("--kill-after=2")
        .arg(FLUSH_TIMEOUT_SECS)
        .arg(RESOLVECTL)
        .arg("flush-caches")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => debug!("flushed systemd-resolved DNS cache"),
        // Non-zero: no systemd-resolved, resolver not running, or a timeout.
        Ok(s) => debug!(%s, "resolvectl flush-caches failed — cached lookups may linger"),
        // Spawn failure: resolvectl (or timeout) isn't installed.
        Err(e) => debug!(?e, "could not run resolvectl — skipping DNS cache flush"),
    }
}
