//! The daemon's recent-event log, as carried in `Status.recent_events`.
//!
//! One bounded, sequence-numbered ring of enforcement events — a refused
//! connection credited by the scheduler, a process killed by procwatch — so
//! a client polling every few seconds can turn each entry into exactly one
//! desktop notification by remembering the highest `seq` it has shown. The
//! sequence, not the timestamp, is the dedup key: two kills in one second are
//! two events.
//!
//! In-memory only, like `health`: a daemon restart empties it and restarts
//! the sequence at 1, which a client reads as "lower than the last seq I saw"
//! and resets to without replaying. Lives behind a leaf `std::sync::Mutex` on
//! `Daemon` (`Daemon::events()`), held for microseconds and never across an
//! await, so it may be taken with `state` already held (the scheduler drain)
//! or on its own (procwatch, `GetStatus`).

use std::collections::VecDeque;

use grepfocus_core::{EventKind, RecentEvent, MAX_EVENT_DETAIL_CHARS};

/// Most events kept, oldest dropped first. A client polls every 5 s and a
/// kill or a credited attempt is at most one per second per source, so 32
/// covers several polls of the busiest plausible second-by-second burst.
pub const RECENT_EVENTS_CAP: usize = 32;

/// The ring and its sequence counter. See the module docs.
#[derive(Debug)]
pub struct Log {
    /// The `seq` the next push gets. Starts at 1: `RecentEvent::default()`
    /// carries 0, so a real event can never be mistaken for a default frame.
    next_seq: u64,
    /// Oldest first.
    ring: VecDeque<RecentEvent>,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            next_seq: 1,
            ring: VecDeque::with_capacity(RECENT_EVENTS_CAP),
        }
    }
}

impl Log {
    /// Append one event at `now` and return its `seq`. `detail` is made safe
    /// for the wire here — control characters dropped, cut at
    /// [`MAX_EVENT_DETAIL_CHARS`] — so no caller can put more than that on
    /// every status frame; what callers pass is already the user's own
    /// blocklist text, never peer-supplied bytes.
    pub fn push(&mut self, kind: EventKind, block_id: u64, detail: &str, now: u64) -> u64 {
        let seq = self.next_seq;
        // Saturating rather than wrapping: a wrap would hand out a `seq`
        // below the last one, which clients read as a daemon restart.
        self.next_seq = self.next_seq.saturating_add(1);
        if self.ring.len() >= RECENT_EVENTS_CAP {
            self.ring.pop_front();
        }
        self.ring.push_back(RecentEvent {
            seq,
            unix: now,
            kind,
            block_id,
            detail: wire_detail(detail),
        });
        seq
    }

    /// Every event still in the ring, oldest first.
    pub fn snapshot(&self) -> Vec<RecentEvent> {
        self.ring.iter().cloned().collect()
    }
}

/// `detail` as it may go on the wire: control characters and the invisible
/// format characters that steer text rendering removed, then at most
/// [`MAX_EVENT_DETAIL_CHARS`] characters. The format characters matter
/// because `detail` ends up in a desktop notification: a bidi override
/// (U+202E) in a user's own matcher text would render the rest of the line
/// reversed, and a zero-width joiner or isolate can hide or splice what it
/// shows. Dropped before the cut, so they never eat the budget either.
fn wire_detail(detail: &str) -> String {
    detail
        .chars()
        .filter(|&c| !c.is_control() && !is_format_or_bidi(c))
        .take(MAX_EVENT_DETAIL_CHARS)
        .collect()
}

/// The zero-width and bidirectional format characters [`wire_detail`] drops:
/// U+200B–U+200F (zero-width space, non-joiner and joiner, LRM, RLM),
/// U+202A–U+202E (the bidi embeddings and overrides) and U+2066–U+2069 (the
/// bidi isolates). None of these is a control character to
/// `char::is_control`, which covers the Cc category only.
fn is_format_or_bidi(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_is_bounded_and_seq_monotonic() {
        let mut log = Log::default();
        assert!(log.snapshot().is_empty());
        // The first event is seq 1, never 0 — 0 is what a default frame reads.
        assert_eq!(log.push(EventKind::Attempt, 7, "reddit.com", 1_000), 1);
        assert_eq!(log.push(EventKind::AppKill, 7, "steam", 1_000), 2);
        let snap = log.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(
            snap[0],
            RecentEvent {
                seq: 1,
                unix: 1_000,
                kind: EventKind::Attempt,
                block_id: 7,
                detail: "reddit.com".into(),
            }
        );
        assert_eq!(snap[1].seq, 2);
        assert_eq!(snap[1].kind, EventKind::AppKill);

        // Fill past the cap: the oldest fall off the front, the sequence
        // keeps climbing, and the snapshot stays oldest-first.
        for i in 3..=(RECENT_EVENTS_CAP as u64 + 10) {
            assert_eq!(log.push(EventKind::Attempt, 1, "x.example", i), i);
        }
        let snap = log.snapshot();
        assert_eq!(snap.len(), RECENT_EVENTS_CAP);
        let seqs: Vec<u64> = snap.iter().map(|e| e.seq).collect();
        let expected: Vec<u64> = (11..=(RECENT_EVENTS_CAP as u64 + 10)).collect();
        assert_eq!(seqs, expected);
    }

    #[test]
    fn detail_is_capped_and_printable() {
        let mut log = Log::default();
        let long = "a".repeat(MAX_EVENT_DETAIL_CHARS + 20);
        log.push(EventKind::Attempt, 1, &long, 0);
        log.push(EventKind::AppKill, 1, "ste\nam\t\u{7f}", 0);
        // Multi-byte characters count as characters, not bytes, so the cut
        // can never split one.
        let wide = "é".repeat(MAX_EVENT_DETAIL_CHARS + 1);
        log.push(EventKind::AppKill, 1, &wide, 0);
        // Zero-width and bidi format characters are not `is_control`, but a
        // bidi override in matcher text would reverse the notification line
        // after it: every range goes, wherever it sits.
        log.push(
            EventKind::AppKill,
            1,
            "\u{202E}st\u{200B}e\u{200F}a\u{2066}m\u{2069}\u{202A}",
            0,
        );
        // Dropped before the cut, so they do not count toward the cap.
        let padded = format!(
            "{}{}",
            "\u{202E}".repeat(10),
            "a".repeat(MAX_EVENT_DETAIL_CHARS)
        );
        log.push(EventKind::Attempt, 1, &padded, 0);
        // The ranges' neighbours — a hair space, a hyphen — are ordinary.
        log.push(EventKind::AppKill, 1, "a\u{200A}b\u{2010}c", 0);
        let snap = log.snapshot();
        assert_eq!(snap[0].detail.chars().count(), MAX_EVENT_DETAIL_CHARS);
        assert_eq!(snap[1].detail, "steam");
        assert_eq!(snap[2].detail.chars().count(), MAX_EVENT_DETAIL_CHARS);
        assert!(snap[2].detail.chars().all(|c| c == 'é'));
        assert_eq!(snap[3].detail, "steam");
        assert_eq!(snap[4].detail.chars().count(), MAX_EVENT_DETAIL_CHARS);
        assert!(snap[4].detail.chars().all(|c| c == 'a'));
        assert_eq!(snap[5].detail, "a\u{200A}b\u{2010}c");
    }
}
