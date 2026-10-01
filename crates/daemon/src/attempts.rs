//! The hand-off between the loopback proxy's accept path and the scheduler
//! tick for refused-connection attempts.
//!
//! The proxy sees every connection it refuses, but it must not touch the
//! state lock (a tokio mutex) from the accept path, and a browser opens many
//! connections per page load. So the hook records into this buffer — behind a
//! leaf `std::sync::Mutex` on `Daemon`, held for microseconds and never across
//! an await, exactly like `forwardable` — and the scheduler tick is the single
//! consumer: it drains the buffer once a second while it already holds `state`
//! and credits what it finds (`scheduler::apply_attempts`).
//!
//! Two bounds make the buffer safe to fill from the network: one attempt per
//! host per [`WINDOW_SECS`] (a page load counts once), and at most
//! [`PENDING_CAP`] counted attempts between two drains (beyond that they are
//! dropped and counted as dropped). The per-host memory is bounded by the set
//! of hosts the daemon is enforcing, because only a canonical blocklist entry
//! is ever recorded (`enforce::canonical_attempt` folds the refused hostname
//! to one, or discards it).
//!
//! Pure: no IO and no clock — `now` is passed in — so every rule is
//! unit-testable.

use std::collections::HashMap;

/// One attempt per host per this many seconds. A page load opens a burst of
/// connections to one host (the document, its assets, retries); the burst is
/// what the user did once, so it counts once.
pub const WINDOW_SECS: u64 = 10;

/// Most counted attempts held between two drains. The scheduler drains every
/// second, so this only bites when hundreds of distinct blocked hosts are hit
/// inside one second — a bound on memory, not a number anyone should reach.
pub const PENDING_CAP: usize = 256;

/// What one drain hands the scheduler.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Drained {
    /// Counted attempts since the last drain, oldest first, each as
    /// `(canonical host, unix seconds)`.
    pub attempts: Vec<(String, u64)>,
    /// Attempts that would have counted but hit [`PENDING_CAP`].
    pub dropped: u64,
}

/// The dedup window plus the pending list. See the module docs.
#[derive(Debug, Default)]
pub struct Buffer {
    /// Per host, the unix second of the last attempt that counted. Entries
    /// older than [`WINDOW_SECS`] are pruned on every drain.
    last: HashMap<String, u64>,
    /// Counted attempts not yet drained, oldest first.
    pending: Vec<(String, u64)>,
    /// Attempts refused at the cap since the last drain.
    dropped: u64,
}

impl Buffer {
    /// Record one refused connection to canonical `host` at `now`. Returns
    /// whether it counted: `false` when another attempt on this host counted
    /// inside the window, or when the pending list is at its cap (then it is
    /// tallied as dropped instead).
    ///
    /// `host` must already be a canonical blocklist entry — it is the caller's
    /// filter that keeps `last` bounded, since this map holds one entry per
    /// distinct host it is ever given.
    ///
    /// The window is `abs_diff`, not a subtraction, for the same reason as
    /// `enforce::needs_probe`: `now` is the wall clock, and after a backward
    /// step the stored stamp sits in the future. A one-sided check would then
    /// suppress the host for the whole magnitude of the step; a divergence of
    /// a window in either direction counts again and re-stamps, so a stepped
    /// clock self-corrects within one window.
    pub fn record(&mut self, host: String, now: u64) -> bool {
        if self
            .last
            .get(&host)
            .is_some_and(|&last| now.abs_diff(last) < WINDOW_SECS)
        {
            return false;
        }
        // The window is consumed whether or not the attempt fits, so under
        // the cap `dropped` counts attempts that WOULD have counted, not every
        // connection of the burst that follows.
        self.last.insert(host.clone(), now);
        if self.pending.len() >= PENDING_CAP {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        self.pending.push((host, now));
        true
    }

    /// Hand over everything counted since the last drain and reset the drop
    /// tally. Also forgets the per-host stamps that have aged past the window
    /// — they could not suppress anything any more, and dropping them here
    /// keeps the map from retaining every host ever attempted.
    pub fn drain(&mut self, now: u64) -> Drained {
        self.last
            .retain(|_, &mut last| now.abs_diff(last) < WINDOW_SECS);
        Drained {
            attempts: std::mem::take(&mut self.pending),
            dropped: std::mem::take(&mut self.dropped),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str) -> String {
        name.to_string()
    }

    #[test]
    fn same_host_within_window_counts_once() {
        let mut b = Buffer::default();
        assert!(b.record(host("reddit.com"), 1_000));
        // The burst behind one page load: every further connection inside
        // the window is the same attempt.
        for t in 1_000..1_000 + WINDOW_SECS {
            assert!(!b.record(host("reddit.com"), t), "at {t}");
        }
        let d = b.drain(1_000 + WINDOW_SECS - 1);
        assert_eq!(d.attempts, vec![(host("reddit.com"), 1_000)]);
        assert_eq!(d.dropped, 0);
    }

    #[test]
    fn window_elapsed_counts_again() {
        let mut b = Buffer::default();
        assert!(b.record(host("reddit.com"), 1_000));
        assert!(b.record(host("reddit.com"), 1_000 + WINDOW_SECS));
        // The second attempt opened a new window of its own.
        assert!(!b.record(host("reddit.com"), 1_000 + WINDOW_SECS + 1));
        let d = b.drain(1_000 + WINDOW_SECS + 1);
        assert_eq!(
            d.attempts,
            vec![
                (host("reddit.com"), 1_000),
                (host("reddit.com"), 1_000 + WINDOW_SECS)
            ]
        );
    }

    #[test]
    fn distinct_hosts_count_separately() {
        let mut b = Buffer::default();
        assert!(b.record(host("reddit.com"), 1_000));
        assert!(b.record(host("twitter.com"), 1_000));
        assert!(!b.record(host("reddit.com"), 1_001));
        assert!(!b.record(host("twitter.com"), 1_001));
        let d = b.drain(1_001);
        assert_eq!(
            d.attempts,
            vec![(host("reddit.com"), 1_000), (host("twitter.com"), 1_000)]
        );
    }

    #[test]
    fn pending_cap_drops_and_counts() {
        let mut b = Buffer::default();
        for i in 0..PENDING_CAP {
            assert!(b.record(format!("site{i}.example"), 1_000));
        }
        // Over the cap: refused, tallied once per host-window — the burst
        // behind the dropped attempt is not tallied again.
        assert!(!b.record(host("one-too-many.example"), 1_000));
        assert!(!b.record(host("one-too-many.example"), 1_001));
        assert!(!b.record(host("two-too-many.example"), 1_000));
        let d = b.drain(1_001);
        assert_eq!(d.attempts.len(), PENDING_CAP);
        assert_eq!(d.dropped, 2);
        // The drain reset both: room again, and a clean tally.
        assert!(b.record(host("after.example"), 1_001));
        let d = b.drain(1_001);
        assert_eq!(d.attempts.len(), 1);
        assert_eq!(d.dropped, 0);
    }

    #[test]
    fn drain_prunes_stale_last_seen() {
        let mut b = Buffer::default();
        b.record(host("old.example"), 1_000);
        b.record(host("fresh.example"), 1_000 + WINDOW_SECS - 1);
        b.drain(1_000 + WINDOW_SECS);
        // The old stamp has aged out of its window; the fresh one is still
        // suppressing.
        assert_eq!(b.last.len(), 1);
        assert!(b.last.contains_key("fresh.example"));
        assert!(!b.record(host("fresh.example"), 1_000 + WINDOW_SECS));
        // An empty drain leaves no attempts and no tally behind.
        assert_eq!(b.drain(1_000 + WINDOW_SECS), Drained::default());
    }

    #[test]
    fn clock_step_backwards_does_not_underflow() {
        let mut b = Buffer::default();
        assert!(b.record(host("reddit.com"), 10_000));
        // A small backward step inside the window still reads as the same
        // attempt — and must not panic on the subtraction.
        assert!(!b.record(host("reddit.com"), 10_000 - WINDOW_SECS + 1));
        // A large backward step counts again rather than suppressing the
        // host for the whole magnitude of the step, and re-stamps at the new
        // time so the window runs from there.
        assert!(b.record(host("reddit.com"), 100));
        assert!(!b.record(host("reddit.com"), 101));
        // Draining at the stepped-back time prunes the future-dated stamp
        // only once it diverges by a window — here it is the fresh one.
        let d = b.drain(101);
        assert_eq!(
            d.attempts,
            vec![(host("reddit.com"), 10_000), (host("reddit.com"), 100)]
        );
        assert_eq!(b.last.len(), 1);
        // And from zero: nothing to underflow into.
        let mut b = Buffer::default();
        assert!(b.record(host("reddit.com"), 0));
        assert!(!b.record(host("reddit.com"), 0));
        assert!(b.drain(0).attempts.len() == 1);
    }
}
