//! What the status watcher tells the user, decided from one status poll to
//! the next.
//!
//! The watcher in `main.rs` polls the daemon every few seconds and hands each
//! successful poll to [`Watch::poll`] as a [`Snapshot`]; back comes the list
//! of desktop notifications to show for that poll. Everything here is pure:
//! the clock is `Snapshot::now` (the daemon's `now_unix`, the same clock that
//! stamps `break_until_unix`, `phase_ends_unix` and every event), there is no
//! IO, and the tests feed snapshots directly.
//!
//! The rules the watcher has always had, now stated once:
//!
//! - the first successful poll only establishes baselines — a GUI started
//!   mid-block must not announce blocks, events or faults that predate it
//!   (the attempts already logged this hour do seed the nudge's count,
//!   silently);
//! - a failed poll never reaches `poll`, so baselines survive a daemon
//!   restart or a transient error without a burst on recovery;
//! - `settings.notifications == false` shows nothing but still advances every
//!   baseline, so turning notifications back on replays nothing;
//! - the master toggle gates every kind; `settings.attempt_nudges` is a
//!   sub-switch for the one chatty kind.
//!
//! Events (`Status.recent_events`) are deduplicated by their daemon-side
//! sequence number: entries with `seq > last_seq` are new. A newest `seq`
//! BELOW `last_seq` means the daemon restarted (its log is in-memory and its
//! counter starts over), so everything it holds was logged since the
//! restart: the baseline drops to zero and those entries are judged like any
//! other — shown once, never replayed. Events older than
//! [`STALE_EVENT_SECS`] are skipped either way — the GUI resumed from sleep
//! and the daemon's log is history, not news (an attempt that old still
//! counts towards the nudge's "Nth this hour").

use std::collections::{HashMap, HashSet, VecDeque};

use grepfocus_core::{
    ActiveBlock, EventKind, Health, NftStatus, Originator, PomodoroPhase, PomodoroStatus,
    RecentEvent, Settings,
};

/// Events this much older than the poll's clock are history: the GUI slept
/// through them.
pub const STALE_EVENT_SECS: u64 = 120;
/// "Break ends in 1 min" fires when the remaining break crosses this edge
/// between two polls; a break never longer than this never warns.
pub const BREAK_WARNING_SECS: u64 = 60;
/// One "App closed" per `(block, app label)` per this long: procwatch dedups
/// a lingering pid, but a relauncher (Steam) loops.
pub const APP_KILL_REPEAT_SECS: u64 = 5 * 60;
/// One attempt nudge per host per this long.
pub const NUDGE_REPEAT_SECS: u64 = 15 * 60;
/// The nudge's "Nth attempt this hour" counts attempts seen within this
/// window.
pub const ATTEMPT_COUNT_SECS: u64 = 60 * 60;
/// Hard cap on the attempts ring, behind the time pruning; the daemon sends at
/// most 32 events per poll, so this is never reached in practice.
const ATTEMPTS_SEEN_CAP: usize = 4096;

/// One successful status poll, reduced to what the notifications need.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    /// The daemon's `now_unix` for this poll — the clock every rule uses.
    pub now: u64,
    pub active: Vec<ActiveBlock>,
    pub pomodoro: Option<PomodoroStatus>,
    pub health: Health,
    /// `Status.recent_events`, oldest first.
    pub events: Vec<RecentEvent>,
}

/// One desktop notification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    pub title: String,
    pub body: String,
}

impl Notice {
    fn new(title: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            body: body.into(),
        }
    }
}

/// The watcher's memory between polls. `Default` is the state before the
/// first successful poll.
#[derive(Default)]
pub struct Watch {
    /// The previous successful poll; `None` until the first one.
    prev: Option<Snapshot>,
    /// Whether the previous poll was RED (see [`enforcement_red`]); `None`
    /// until the first one. Only the false→true edge notifies: the fault
    /// stays up until it clears, so repeating it every poll would be noise.
    prev_red: Option<bool>,
    /// Newest event `seq` already accounted for; `None` until the first poll.
    last_seq: Option<u64>,
    /// `(block id, break_until_unix)` pairs whose one-minute warning fired.
    warned_breaks: HashSet<(u64, u64)>,
    /// Block ids whose next disappearance is NOT a "Block ended": a pomodoro
    /// completion or stop already said what happened. Every entry belongs to
    /// a block running as of the last poll; the end loop prunes the rest.
    suppress_ended: HashSet<u64>,
    /// host → clock of its last nudge.
    nudged: HashMap<String, u64>,
    /// `(block id, app label)` → clock of its last "App closed".
    app_notified: HashMap<(u64, String), u64>,
    /// `(event unix, host)` of every attempt event seen, oldest first; the
    /// "Nth attempt this hour" counter.
    attempts_seen: VecDeque<(u64, String)>,
}

impl Watch {
    /// Everything to show for `cur` given the previous poll. Pure: the clock
    /// is `cur.now`. Always advances baselines; `settings` only decides what
    /// is returned (and, for the rate-limited kinds, what counts as shown).
    pub fn poll(&mut self, cur: Snapshot, settings: &Settings) -> Vec<Notice> {
        let now = cur.now;
        let show = settings.notifications;
        let show_nudges = show && settings.attempt_nudges;
        let mut out = Vec::new();

        self.prune(now);

        let domain_block_active = cur.active.iter().any(|a| !a.block.domains.is_empty());
        let red = enforcement_red(&cur.health, domain_block_active);
        let newest_seq = cur.events.iter().map(|e| e.seq).max().unwrap_or(0);

        let Some(prev) = self.prev.take() else {
            // First successful poll: baselines only — but the attempts the
            // daemon already logged this hour count, or the first nudge after
            // a GUI start would undercount.
            for e in &cur.events {
                self.record_attempt(e, now);
            }
            self.last_seq = Some(newest_seq);
            self.prev_red = Some(red.is_some());
            self.prev = Some(cur);
            return out;
        };

        let name_of = |id: u64| -> Option<String> {
            cur.active
                .iter()
                .chain(prev.active.iter())
                .find(|a| a.block.id == id)
                .map(|a| a.block.name.clone())
        };
        let name_or_id = |id: u64| name_of(id).unwrap_or_else(|| format!("block {id}"));

        // Block started: in this poll, not the last.
        for a in &cur.active {
            if !prev.active.iter().any(|p| p.block.id == a.block.id) && show {
                out.push(Notice::new("Block started", a.block.name.clone()));
            }
        }

        // Pomodoro phase changes, completion and stop — judged on the
        // session that was running last poll.
        if let Some(pa) = &prev.pomodoro {
            let name = name_or_id(pa.block_id);
            match cur.pomodoro.as_ref().filter(|p| p.block_id == pa.block_id) {
                Some(pb) => {
                    let cycle = format!("cycle {} of {}", pb.cycle_index + 1, pb.cycles_total);
                    let notice = match (pa.phase, pb.phase) {
                        (PomodoroPhase::Focus, PomodoroPhase::Break) => {
                            // The wire carries the phase end, not the break
                            // length: round what is left to whole minutes.
                            let left = pb.phase_ends_unix.saturating_sub(now);
                            let minutes = ((left + 30) / 60).max(1);
                            Some(Notice::new(
                                "Break time",
                                format!("{name}: {minutes} min break, {cycle}"),
                            ))
                        }
                        (PomodoroPhase::Break, PomodoroPhase::Focus) => {
                            Some(Notice::new("Focus time", format!("{name}: {cycle}")))
                        }
                        _ => None,
                    };
                    if show {
                        out.extend(notice);
                    }
                }
                // The block already left `active` last poll — the daemon can
                // drop an expired block a tick before the session that drove
                // it goes (a restart, a suspend past the set's backstop): its
                // "Block ended" was said then, and the session's disappearance
                // now is the tail of that, not a completion or a stop.
                None if !prev.active.iter().any(|a| a.block.id == pa.block_id) => {}
                None => match pa.phase {
                    // The last focus interval ran out: the set is done and
                    // the block's expiry is its natural end, not news.
                    PomodoroPhase::Focus if pa.cycle_index + 1 >= pa.cycles_total => {
                        self.suppress_ended.insert(pa.block_id);
                        if show {
                            let n = pa.cycles_total;
                            let cycles = if n == 1 { "cycle" } else { "cycles" };
                            out.push(Notice::new(
                                "Pomodoro complete",
                                format!("{name}: {n} {cycles} done"),
                            ));
                        }
                    }
                    // `stop_pomodoro` (only allowed during a break) clears the
                    // session and ends the block in one save.
                    PomodoroPhase::Break => {
                        self.suppress_ended.insert(pa.block_id);
                        if show {
                            out.push(Notice::new("Pomodoro stopped", name));
                        }
                    }
                    // A session dropped mid-set (the block was ended some
                    // other way): the plain "Block ended" tells it.
                    PomodoroPhase::Focus => {}
                },
            }
        }

        // Block ended: in the last poll, not this one — unless a pomodoro
        // notice above already covered it.
        for p in &prev.active {
            if cur.active.iter().any(|a| a.block.id == p.block.id) {
                continue;
            }
            if self.suppress_ended.remove(&p.block.id) {
                continue;
            }
            if show {
                out.push(Notice::new("Block ended", p.block.name.clone()));
            }
        }
        // Every suppression belongs to a block still running; one left over
        // would swallow that id's NEXT "Block ended".
        self.suppress_ended
            .retain(|id| cur.active.iter().any(|a| a.block.id == *id));

        // Breaks: the one-minute warning on the edge, and "Break over" when a
        // break ends with the block still running.
        for b in &cur.active {
            let Some(a) = prev.active.iter().find(|a| a.block.id == b.block.id) else {
                continue;
            };
            let before = break_remaining(a, prev.now);
            let after = break_remaining(b, now);
            match (before, after) {
                (Some(before), Some(after))
                    if before > BREAK_WARNING_SECS && after <= BREAK_WARNING_SECS =>
                {
                    let until = b.break_until_unix.unwrap_or_default();
                    if self.warned_breaks.insert((b.block.id, until)) && show {
                        out.push(Notice::new(
                            "Break ends in 1 min",
                            format!("{} will be blocked again", b.block.name),
                        ));
                    }
                }
                (Some(_), None) => {
                    // A pomodoro-driven break ends with "Focus time" above.
                    let pomodoro_driven = b.originator == Originator::Pomodoro
                        || prev
                            .pomodoro
                            .as_ref()
                            .is_some_and(|p| p.block_id == b.block.id)
                        || cur
                            .pomodoro
                            .as_ref()
                            .is_some_and(|p| p.block_id == b.block.id);
                    if !pomodoro_driven && show {
                        out.push(Notice::new(
                            "Break over",
                            format!("{} is blocked again", b.block.name),
                        ));
                    }
                }
                _ => {}
            }
        }

        // Daemon events, deduplicated by sequence number.
        let mut last_seq = self.last_seq.unwrap_or(0);
        if newest_seq < last_seq {
            // The daemon restarted (its counter starts over; an empty log is
            // the same signal). Its log is in-memory, so everything in it
            // was logged since: judge it all — the stale bound still applies.
            last_seq = 0;
        }
        for e in cur.events.iter().filter(|e| e.seq > last_seq) {
            // Counted whether or not it is shown — or stale: the count
            // is of attempts, not of nudges.
            self.record_attempt(e, now);
            // History the GUI slept through, or nothing to say.
            if now.saturating_sub(e.unix) > STALE_EVENT_SECS || e.detail.is_empty() {
                continue;
            }
            match e.kind {
                EventKind::AppKill => {
                    if !show {
                        continue;
                    }
                    let key = (e.block_id, e.detail.clone());
                    if self
                        .app_notified
                        .get(&key)
                        .is_some_and(|&t| now.saturating_sub(t) < APP_KILL_REPEAT_SECS)
                    {
                        continue;
                    }
                    self.app_notified.insert(key, now);
                    let body = match name_of(e.block_id) {
                        Some(name) => format!("GrepFocus closed {} ({name})", e.detail),
                        None => format!("GrepFocus closed {}", e.detail),
                    };
                    out.push(Notice::new("App closed", body));
                }
                EventKind::Attempt => {
                    if !show_nudges {
                        continue;
                    }
                    if self
                        .nudged
                        .get(&e.detail)
                        .is_some_and(|&t| now.saturating_sub(t) < NUDGE_REPEAT_SECS)
                    {
                        continue;
                    }
                    self.nudged.insert(e.detail.clone(), now);
                    let n = self
                        .attempts_seen
                        .iter()
                        .filter(|(t, host)| {
                            host == &e.detail && now.saturating_sub(*t) < ATTEMPT_COUNT_SECS
                        })
                        .count();
                    let body = match name_of(e.block_id) {
                        Some(name) => format!("{n}{} attempt this hour · {name}", ordinal(n)),
                        None => format!("{n}{} attempt this hour", ordinal(n)),
                    };
                    out.push(Notice::new(format!("{} blocked", e.detail), body));
                }
                EventKind::Unknown => {}
            }
        }
        self.last_seq = Some(newest_seq.max(last_seq));

        // Enforcement newly RED.
        if let (Some(false), Some(body)) = (self.prev_red, red) {
            if show {
                out.push(Notice::new("GrepFocus: blocking problem", body));
            }
        }

        self.prev_red = Some(red.is_some());
        self.prev = Some(cur);
        out
    }

    /// Remember an attempt for the "Nth attempt this hour" count. Any other
    /// kind, or an attempt already outside the window, is ignored.
    fn record_attempt(&mut self, e: &RecentEvent, now: u64) {
        if e.kind != EventKind::Attempt || now.saturating_sub(e.unix) >= ATTEMPT_COUNT_SECS {
            return;
        }
        self.attempts_seen.push_back((e.unix, e.detail.clone()));
        if self.attempts_seen.len() > ATTEMPTS_SEEN_CAP {
            self.attempts_seen.pop_front();
        }
    }

    /// Drop memory that can no longer matter, so every container stays
    /// bounded by the clock.
    fn prune(&mut self, now: u64) {
        self.warned_breaks.retain(|&(_, until)| until > now);
        self.app_notified
            .retain(|_, &mut t| now.saturating_sub(t) < APP_KILL_REPEAT_SECS);
        self.nudged
            .retain(|_, &mut t| now.saturating_sub(t) < NUDGE_REPEAT_SECS);
        while let Some((t, _)) = self.attempts_seen.front() {
            if now.saturating_sub(*t) >= ATTEMPT_COUNT_SECS {
                self.attempts_seen.pop_front();
            } else {
                break;
            }
        }
    }
}

/// Seconds of break left for `a` at `at`, or `None` when it is not on a
/// break (the daemon's own rule: `break_until_unix` set and `> now`).
fn break_remaining(a: &ActiveBlock, at: u64) -> Option<u64> {
    a.break_until_unix.filter(|&t| t > at).map(|t| t - at)
}

/// English ordinal suffix: 1st, 2nd, 3rd, 4th, 11th, 12th, 13th, 21st, 111th.
fn ordinal(n: usize) -> &'static str {
    match (n % 10, n % 100) {
        (_, 11..=13) => "th",
        (1, _) => "st",
        (2, _) => "nd",
        (3, _) => "rd",
        _ => "th",
    }
}

/// The notification body while enforcement is in a RED state, `None`
/// otherwise. Mirrors exactly the two RED rules of `healthNotices` in
/// ui/src/logic/health.ts — change together: a state the banner paints red
/// that this does not (or the reverse) is a notification the window cannot
/// explain. Silent on a daemon too old to report (empty `daemon_version`).
fn enforcement_red(health: &Health, domain_block_active: bool) -> Option<&'static str> {
    if health.daemon_version.is_empty() {
        return None;
    }
    if health.last_error.is_some() {
        return Some(
            "The /etc/hosts change could not be applied — website blocking may not be enforced. Open GrepFocus for details.",
        );
    }
    if domain_block_active && matches!(health.nft, NftStatus::Failed { .. }) {
        return Some(
            "DoH protection (nftables) failed — browsers using DNS-over-HTTPS can bypass the active block. Open GrepFocus for details.",
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{enforcement_red, ordinal, Notice, Snapshot, Watch};
    use grepfocus_core::{
        ActiveBlock, Block, EventKind, Health, NftStatus, Originator, PomodoroPhase,
        PomodoroStatus, RecentEvent, Settings,
    };

    // ── the one snapshot builder ────────────────────────────────────────

    /// Builds one poll. Every test describes its polls with this and nothing
    /// else; there is no clock — `at(now)` is the clock.
    struct Snap(Snapshot);

    fn at(now: u64) -> Snap {
        Snap(Snapshot {
            now,
            health: reporting(),
            ..Snapshot::default()
        })
    }

    impl Snap {
        fn with_block(mut self, id: u64, name: &str, originator: Originator) -> Self {
            self.0.active.push(ActiveBlock {
                block: Block {
                    id,
                    name: name.to_string(),
                    domains: vec!["example.test".to_string()],
                    ..Block::default()
                },
                started_at_unix: 0,
                ends_at_unix: u64::MAX,
                originator,
                break_until_unix: None,
                apps_enforced: false,
                lock: Default::default(),
                allowance: None,
                attempts: 0,
            });
            self
        }

        /// A manually started block with one domain.
        fn block(self, id: u64, name: &str) -> Self {
            self.with_block(id, name, Originator::Manual)
        }

        /// A block driven by a pomodoro session.
        fn pomodoro_block(self, id: u64, name: &str) -> Self {
            self.with_block(id, name, Originator::Pomodoro)
        }

        /// Put block `id` on a break until `until`.
        fn on_break(mut self, id: u64, until: u64) -> Self {
            let a = self
                .0
                .active
                .iter_mut()
                .find(|a| a.block.id == id)
                .expect("on_break: add the block first");
            a.break_until_unix = Some(until);
            self
        }

        fn pomodoro(
            mut self,
            block_id: u64,
            phase: PomodoroPhase,
            phase_ends_unix: u64,
            cycle_index: u32,
            cycles_total: u32,
        ) -> Self {
            self.0.pomodoro = Some(PomodoroStatus {
                block_id,
                phase,
                phase_ends_unix,
                cycle_index,
                cycles_total,
            });
            self
        }

        fn health(mut self, health: Health) -> Self {
            self.0.health = health;
            self
        }

        fn event(
            mut self,
            seq: u64,
            unix: u64,
            kind: EventKind,
            block_id: u64,
            detail: &str,
        ) -> Self {
            self.0.events.push(RecentEvent {
                seq,
                unix,
                kind,
                block_id,
                detail: detail.to_string(),
            });
            self
        }

        fn build(self) -> Snapshot {
            self.0
        }
    }

    // ── settings and helpers ────────────────────────────────────────────

    /// Notifications on, nudges off: the shipped default.
    fn on() -> Settings {
        Settings::default()
    }

    fn off() -> Settings {
        Settings {
            notifications: false,
            ..Settings::default()
        }
    }

    fn nudges() -> Settings {
        Settings {
            attempt_nudges: true,
            ..Settings::default()
        }
    }

    /// A daemon new enough to report health, everything else at rest.
    fn reporting() -> Health {
        Health {
            daemon_version: "0.5.1".to_string(),
            ..Health::default()
        }
    }

    fn hosts_error() -> Health {
        Health {
            last_error: Some("hosts: read-only file system".to_string()),
            ..reporting()
        }
    }

    fn nft_failed() -> Health {
        Health {
            nft: NftStatus::Failed {
                reason: "nft: command not found".to_string(),
            },
            ..reporting()
        }
    }

    fn pairs(notices: &[Notice]) -> Vec<(&str, &str)> {
        notices
            .iter()
            .map(|n| (n.title.as_str(), n.body.as_str()))
            .collect()
    }

    fn titles(notices: &[Notice]) -> Vec<&str> {
        notices.iter().map(|n| n.title.as_str()).collect()
    }

    // ── tests ───────────────────────────────────────────────────────────

    #[test]
    fn first_poll_is_silent_and_sets_baselines() {
        let mut w = Watch::default();
        // A GUI started mid-session: a running block, a running pomodoro,
        // events already logged, and a fault already up.
        let busy = |now: u64| {
            at(now)
                .block(1, "Work")
                .pomodoro_block(2, "Deep")
                .pomodoro(2, PomodoroPhase::Focus, now + 900, 0, 4)
                .health(hosts_error())
                .event(1, now, EventKind::AppKill, 1, "steam")
                .event(2, now, EventKind::Attempt, 1, "reddit.com")
                .event(3, now, EventKind::AppKill, 1, "discord")
        };
        assert!(w.poll(busy(1_000).build(), &nudges()).is_empty());
        // Nothing changed: still nothing — no replay of the baseline.
        assert!(w.poll(busy(1_005).build(), &nudges()).is_empty());
        // The baselines are live: what changes from here is news.
        let next = at(1_010)
            .pomodoro_block(2, "Deep")
            .pomodoro(2, PomodoroPhase::Focus, 1_910, 0, 4)
            .health(hosts_error())
            .event(3, 1_000, EventKind::AppKill, 1, "discord")
            .event(4, 1_010, EventKind::AppKill, 1, "steam")
            .build();
        assert_eq!(
            pairs(&w.poll(next, &nudges())),
            vec![
                ("Block ended", "Work"),
                ("App closed", "GrepFocus closed steam (Work)"),
            ]
        );
    }

    #[test]
    fn block_start_and_end_unchanged() {
        let mut w = Watch::default();
        assert!(w.poll(at(100).build(), &on()).is_empty());
        assert_eq!(
            pairs(&w.poll(at(105).block(1, "Work").build(), &on())),
            vec![("Block started", "Work")]
        );
        assert_eq!(
            pairs(&w.poll(at(110).block(1, "Work").block(2, "Social").build(), &on())),
            vec![("Block started", "Social")]
        );
        // Unchanged poll: silence.
        assert!(w
            .poll(at(115).block(1, "Work").block(2, "Social").build(), &on())
            .is_empty());
        // Both gone, reported in the order they were listed.
        assert_eq!(
            pairs(&w.poll(at(120).build(), &on())),
            vec![("Block ended", "Work"), ("Block ended", "Social")]
        );
    }

    #[test]
    fn pomodoro_phase_changes_notify_once_each() {
        let mut w = Watch::default();
        let focus = at(1_000)
            .pomodoro_block(7, "Deep")
            .pomodoro(7, PomodoroPhase::Focus, 2_500, 0, 4)
            .build();
        assert!(w.poll(focus, &on()).is_empty());

        // Focus → break: the daemon put the block on a break and the session
        // in the break phase in the same tick. Polled 4 s into a 300 s break
        // the copy still says 5 min.
        let brk = |now: u64| {
            at(now)
                .pomodoro_block(7, "Deep")
                .on_break(7, 2_800)
                .pomodoro(7, PomodoroPhase::Break, 2_800, 0, 4)
        };
        assert_eq!(
            pairs(&w.poll(brk(2_504).build(), &on())),
            vec![("Break time", "Deep: 5 min break, cycle 1 of 4")]
        );
        // Same phase again: once.
        assert!(w.poll(brk(2_509).build(), &on()).is_empty());

        // Break → focus: the daemon bumped the cycle and cleared the break.
        let focus2 = |now: u64| {
            at(now)
                .pomodoro_block(7, "Deep")
                .pomodoro(7, PomodoroPhase::Focus, 4_300, 1, 4)
        };
        assert_eq!(
            pairs(&w.poll(focus2(2_803).build(), &on())),
            vec![("Focus time", "Deep: cycle 2 of 4")]
        );
        assert!(w.poll(focus2(2_808).build(), &on()).is_empty());
    }

    #[test]
    fn pomodoro_completion_replaces_block_ended() {
        // The daemon clears the session and drops its block in the same
        // tick: one "Pomodoro complete", no "Block ended".
        let mut w = Watch::default();
        let last_focus = at(1_000)
            .pomodoro_block(7, "Deep")
            .pomodoro(7, PomodoroPhase::Focus, 1_004, 3, 4)
            .build();
        assert!(w.poll(last_focus, &on()).is_empty());
        assert_eq!(
            pairs(&w.poll(at(1_005).build(), &on())),
            vec![("Pomodoro complete", "Deep: 4 cycles done")]
        );

        // Should the block ever outlive its session by a poll, the
        // completion is still said once and covers the block's later end.
        let mut w = Watch::default();
        let last_focus = at(1_000)
            .pomodoro_block(7, "Deep")
            .pomodoro(7, PomodoroPhase::Focus, 1_004, 3, 4)
            .build();
        assert!(w.poll(last_focus, &on()).is_empty());
        assert_eq!(
            pairs(&w.poll(at(1_005).pomodoro_block(7, "Deep").build(), &on())),
            vec![("Pomodoro complete", "Deep: 4 cycles done")]
        );
        assert!(w.poll(at(1_010).build(), &on()).is_empty());

        // A one-cycle set reads as one cycle.
        let mut w = Watch::default();
        let only_focus = at(1_000)
            .pomodoro_block(7, "Deep")
            .pomodoro(7, PomodoroPhase::Focus, 1_004, 0, 1)
            .build();
        assert!(w.poll(only_focus, &on()).is_empty());
        assert_eq!(
            pairs(&w.poll(at(1_005).build(), &on())),
            vec![("Pomodoro complete", "Deep: 1 cycle done")]
        );

        // A session dropped mid-set (block ended some other way) is not a
        // completion: the plain "Block ended" tells it.
        let mut w = Watch::default();
        let mid_focus = at(1_000)
            .pomodoro_block(7, "Deep")
            .pomodoro(7, PomodoroPhase::Focus, 2_000, 1, 4)
            .build();
        assert!(w.poll(mid_focus, &on()).is_empty());
        assert_eq!(
            pairs(&w.poll(at(1_005).build(), &on())),
            vec![("Block ended", "Deep")]
        );
    }

    #[test]
    fn pomodoro_stop_replaces_block_ended() {
        // `stop_pomodoro` clears the session and sets the block's end to now;
        // reconcile drops the block on its next tick. Whether the GUI sees
        // the block linger (still on its break) or not, exactly one
        // "Pomodoro stopped" and never "Break over" or "Block ended".
        let mut w = Watch::default();
        let in_break = at(1_000)
            .pomodoro_block(7, "Deep")
            .on_break(7, 1_300)
            .pomodoro(7, PomodoroPhase::Break, 1_300, 1, 4)
            .build();
        assert!(w.poll(in_break, &on()).is_empty());
        assert_eq!(
            pairs(
                &w.poll(
                    at(1_005)
                        .pomodoro_block(7, "Deep")
                        .on_break(7, 1_300)
                        .build(),
                    &on()
                )
            ),
            vec![("Pomodoro stopped", "Deep")]
        );
        assert!(w.poll(at(1_010).build(), &on()).is_empty());

        let mut w = Watch::default();
        let in_break = at(1_000)
            .pomodoro_block(7, "Deep")
            .on_break(7, 1_300)
            .pomodoro(7, PomodoroPhase::Break, 1_300, 1, 4)
            .build();
        assert!(w.poll(in_break, &on()).is_empty());
        assert_eq!(
            pairs(&w.poll(at(1_005).build(), &on())),
            vec![("Pomodoro stopped", "Deep")]
        );
    }

    #[test]
    fn session_pruned_after_its_block_already_ended_is_not_news() {
        // The daemon can drop an expired pomodoro block a tick before the
        // session that drove it goes (a restart, a suspend past the set's
        // backstop). The block's end is the news; the session's
        // disappearance afterwards is neither a completion nor a stop — and
        // it must not swallow the block's NEXT end.
        let mut w = Watch::default();
        let last_focus = |now: u64| {
            at(now)
                .pomodoro_block(7, "Deep")
                .pomodoro(7, PomodoroPhase::Focus, 1_004, 3, 4)
        };
        assert!(w.poll(last_focus(1_000).build(), &on()).is_empty());
        // Block gone, session still reported.
        assert_eq!(
            pairs(
                &w.poll(
                    at(1_005)
                        .pomodoro(7, PomodoroPhase::Focus, 1_004, 3, 4)
                        .build(),
                    &on()
                )
            ),
            vec![("Block ended", "Deep")]
        );
        // Session gone too: nothing more to say.
        assert!(w.poll(at(1_010).build(), &on()).is_empty());
        // The same block later: started and ended like any other.
        assert_eq!(
            pairs(&w.poll(at(5_000).block(7, "Deep").build(), &on())),
            vec![("Block started", "Deep")]
        );
        assert_eq!(
            pairs(&w.poll(at(5_005).build(), &on())),
            vec![("Block ended", "Deep")]
        );

        // The same from a break: no "Pomodoro stopped" either.
        let mut w = Watch::default();
        let in_break = at(1_000)
            .pomodoro_block(7, "Deep")
            .on_break(7, 1_300)
            .pomodoro(7, PomodoroPhase::Break, 1_300, 1, 4)
            .build();
        assert!(w.poll(in_break, &on()).is_empty());
        assert_eq!(
            pairs(
                &w.poll(
                    at(1_005)
                        .pomodoro(7, PomodoroPhase::Break, 1_300, 1, 4)
                        .build(),
                    &on()
                )
            ),
            vec![("Block ended", "Deep")]
        );
        assert!(w.poll(at(1_010).build(), &on()).is_empty());
        assert_eq!(
            pairs(&w.poll(at(5_000).block(7, "Deep").build(), &on())),
            vec![("Block started", "Deep")]
        );
        assert_eq!(
            pairs(&w.poll(at(5_005).build(), &on())),
            vec![("Block ended", "Deep")]
        );
    }

    #[test]
    fn break_warning_fires_once_on_the_60s_edge_and_never_for_short_breaks() {
        let mut w = Watch::default();
        assert!(w.poll(at(1_000).block(1, "Work").build(), &on()).is_empty());

        // A 2-minute break from 1_000: remaining 120 → 65 → 59 → 54 → over.
        let brk = |now: u64| at(now).block(1, "Work").on_break(1, 1_120);
        assert!(w.poll(brk(1_000).build(), &on()).is_empty());
        assert!(w.poll(brk(1_055).build(), &on()).is_empty());
        assert_eq!(
            pairs(&w.poll(brk(1_061).build(), &on())),
            vec![("Break ends in 1 min", "Work will be blocked again")]
        );
        // Still under a minute: the warning does not repeat.
        assert!(w.poll(brk(1_066).build(), &on()).is_empty());
        assert_eq!(
            pairs(&w.poll(at(1_121).block(1, "Work").build(), &on())),
            vec![("Break over", "Work is blocked again")]
        );

        // A 45-second break never has more than a minute left, so it never
        // warns — it only ends.
        let short = |now: u64| at(now).block(1, "Work").on_break(1, 2_045);
        assert!(w.poll(short(2_000).build(), &on()).is_empty());
        assert!(w.poll(short(2_005).build(), &on()).is_empty());
        assert!(w.poll(short(2_040).build(), &on()).is_empty());
        assert_eq!(
            titles(&w.poll(at(2_046).block(1, "Work").build(), &on())),
            vec!["Break over"]
        );

        // Exactly 60 s: the edge is "more than a minute" to "a minute or
        // less", which a 60-s break never crosses.
        let minute = |now: u64| at(now).block(1, "Work").on_break(1, 3_060);
        assert!(w.poll(minute(3_000).build(), &on()).is_empty());
        assert!(w.poll(minute(3_005).build(), &on()).is_empty());

        // A break that ends together with its block is a "Block ended",
        // not a "Break over".
        assert_eq!(
            titles(&w.poll(at(3_061).build(), &on())),
            vec!["Block ended"]
        );
    }

    #[test]
    fn break_warning_also_fires_for_pomodoro_breaks() {
        // A pomodoro break longer than a minute warns like any other break —
        // the block is about to be enforced again either way. Only its end
        // differs ("Focus time", see break_over_skips_pomodoro_blocks).
        let mut w = Watch::default();
        let brk = |now: u64| {
            at(now)
                .pomodoro_block(7, "Deep")
                .on_break(7, 1_300)
                .pomodoro(7, PomodoroPhase::Break, 1_300, 0, 4)
        };
        assert!(w.poll(brk(1_000).build(), &on()).is_empty());
        assert!(w.poll(brk(1_235).build(), &on()).is_empty());
        assert_eq!(
            pairs(&w.poll(brk(1_241).build(), &on())),
            vec![("Break ends in 1 min", "Deep will be blocked again")]
        );
        assert!(w.poll(brk(1_246).build(), &on()).is_empty());
    }

    #[test]
    fn break_over_skips_pomodoro_blocks() {
        let mut w = Watch::default();
        // A manual block and a pomodoro block both on a break.
        let both = at(1_000)
            .block(1, "Work")
            .on_break(1, 1_200)
            .pomodoro_block(7, "Deep")
            .on_break(7, 1_200)
            .pomodoro(7, PomodoroPhase::Break, 1_200, 0, 4)
            .build();
        assert!(w.poll(both, &on()).is_empty());
        // Both breaks end: the manual one says "Break over", the pomodoro one
        // says "Focus time" and nothing else.
        let resumed = at(1_203)
            .block(1, "Work")
            .pomodoro_block(7, "Deep")
            .pomodoro(7, PomodoroPhase::Focus, 2_700, 1, 4)
            .build();
        assert_eq!(
            pairs(&w.poll(resumed, &on())),
            vec![
                ("Focus time", "Deep: cycle 2 of 4"),
                ("Break over", "Work is blocked again"),
            ]
        );
    }

    #[test]
    fn app_kill_events_dedup_by_seq_and_rate_limit() {
        let mut w = Watch::default();
        assert!(w.poll(at(1_000).block(1, "Work").build(), &on()).is_empty());

        let kill = |now: u64| at(now).block(1, "Work");
        assert_eq!(
            pairs(
                &w.poll(
                    kill(1_005)
                        .event(1, 1_004, EventKind::AppKill, 1, "steam")
                        .build(),
                    &on()
                )
            ),
            vec![("App closed", "GrepFocus closed steam (Work)")]
        );
        // The same entry on the next poll is not new.
        assert!(w
            .poll(
                kill(1_010)
                    .event(1, 1_004, EventKind::AppKill, 1, "steam")
                    .build(),
                &on()
            )
            .is_empty());
        // A new kill of the same app within 5 min: rate-limited (a
        // relauncher loops); a different app is its own key; an unknown
        // kind says nothing.
        assert_eq!(
            pairs(
                &w.poll(
                    kill(1_015)
                        .event(1, 1_004, EventKind::AppKill, 1, "steam")
                        .event(2, 1_014, EventKind::AppKill, 1, "steam")
                        .event(3, 1_014, EventKind::AppKill, 1, "discord")
                        .event(4, 1_014, EventKind::Unknown, 1, "whatever")
                        .build(),
                    &on()
                )
            ),
            vec![("App closed", "GrepFocus closed discord (Work)")]
        );
        // After 5 min the same app notifies again; a kill for a block the
        // GUI no longer sees names no block.
        assert_eq!(
            pairs(
                &w.poll(
                    kill(1_306)
                        .event(5, 1_305, EventKind::AppKill, 1, "steam")
                        .event(6, 1_305, EventKind::AppKill, 9, "vlc")
                        .build(),
                    &on()
                )
            ),
            vec![
                ("App closed", "GrepFocus closed steam (Work)"),
                ("App closed", "GrepFocus closed vlc"),
            ]
        );
    }

    #[test]
    fn attempt_nudge_needs_both_toggles_counts_per_hour_and_rate_limits() {
        let mut w = Watch::default();
        // A GUI started with two attempts already in the daemon's log this
        // hour: silent, but they count.
        let seeded = at(1_000)
            .block(1, "Work")
            .event(1, 990, EventKind::Attempt, 1, "reddit.com")
            .event(2, 995, EventKind::Attempt, 1, "reddit.com")
            .build();
        assert!(w.poll(seeded, &nudges()).is_empty());
        let poll = |now: u64, seq: u64, host: &str| {
            at(now)
                .block(1, "Work")
                .event(seq, now, EventKind::Attempt, 1, host)
                .build()
        };

        // Nudges off (the default): nothing. Master off with nudges on:
        // nothing. Both seen attempts still count.
        assert!(w.poll(poll(1_005, 3, "x.com"), &on()).is_empty());
        assert!(w
            .poll(
                poll(1_010, 4, "x.com"),
                &Settings {
                    notifications: false,
                    attempt_nudges: true,
                    ..Settings::default()
                }
            )
            .is_empty());
        // The first nudge counts the two attempts from before the GUI
        // started.
        assert_eq!(
            pairs(&w.poll(poll(1_015, 5, "reddit.com"), &nudges())),
            vec![("reddit.com blocked", "3rd attempt this hour · Work")]
        );
        // Within 15 min of the last nudge for that host: silent, still
        // counted. Another host is its own limit, and the attempts seen
        // while the toggles were off count towards it.
        assert!(w.poll(poll(1_075, 6, "reddit.com"), &nudges()).is_empty());
        assert_eq!(
            pairs(&w.poll(poll(1_080, 7, "x.com"), &nudges())),
            vec![("x.com blocked", "3rd attempt this hour · Work")]
        );
        // 15 min later: the 5th of the hour.
        assert_eq!(
            pairs(&w.poll(poll(1_915, 8, "reddit.com"), &nudges())),
            vec![("reddit.com blocked", "5th attempt this hour · Work")]
        );
        // An hour on, the early attempts have aged out of the count. The
        // GUI slept through one (stale: no nudge, but counted), so the fresh
        // one is the 3rd with the one at 1_915.
        let woke = at(4_700)
            .block(1, "Work")
            .event(9, 4_500, EventKind::Attempt, 1, "reddit.com")
            .event(10, 4_700, EventKind::Attempt, 1, "reddit.com")
            .build();
        assert_eq!(
            pairs(&w.poll(woke, &nudges())),
            vec![("reddit.com blocked", "3rd attempt this hour · Work")]
        );
        // A block the GUI cannot name leaves the name off.
        assert_eq!(
            pairs(
                &w.poll(
                    at(4_705)
                        .block(1, "Work")
                        .event(11, 4_705, EventKind::Attempt, 42, "news.test")
                        .build(),
                    &nudges()
                )
            ),
            vec![("news.test blocked", "1st attempt this hour")]
        );
    }

    #[test]
    fn daemon_restart_resets_seq_without_replay() {
        let mut w = Watch::default();
        let kills = |now: u64, entries: &[(u64, &str)]| {
            entries
                .iter()
                .fold(at(now).block(1, "Work"), |s, &(seq, app)| {
                    s.event(seq, now, EventKind::AppKill, 1, app)
                })
                .build()
        };
        assert!(w
            .poll(kills(1_000, &[(10, "steam"), (11, "discord")]), &on())
            .is_empty());
        assert_eq!(
            pairs(&w.poll(
                kills(1_005, &[(10, "steam"), (11, "discord"), (12, "vlc")]),
                &on()
            )),
            vec![("App closed", "GrepFocus closed vlc (Work)")]
        );

        // The daemon restarted (its counter started over) and has logged
        // since. Its log holds nothing from before the restart, so what is
        // there is news — once.
        assert_eq!(
            pairs(&w.poll(kills(1_010, &[(1, "zoom"), (2, "slack")]), &on())),
            vec![
                ("App closed", "GrepFocus closed zoom (Work)"),
                ("App closed", "GrepFocus closed slack (Work)"),
            ]
        );
        assert_eq!(
            pairs(&w.poll(
                kills(1_015, &[(1, "zoom"), (2, "slack"), (3, "spotify")]),
                &on()
            )),
            vec![("App closed", "GrepFocus closed spotify (Work)")]
        );

        // Restarted while the GUI slept: the stale bound still applies to
        // what the new log holds.
        let woke = at(5_000)
            .block(1, "Work")
            .event(1, 5_000 - 121, EventKind::AppKill, 1, "old")
            .event(2, 5_000 - 60, EventKind::AppKill, 1, "fresh")
            .build();
        assert_eq!(
            pairs(&w.poll(woke, &on())),
            vec![("App closed", "GrepFocus closed fresh (Work)")]
        );

        // Restarted again, its log still empty: the first entry afterwards
        // is news.
        assert!(w.poll(kills(5_005, &[]), &on()).is_empty());
        assert_eq!(
            pairs(&w.poll(kills(5_010, &[(1, "chrome")]), &on())),
            vec![("App closed", "GrepFocus closed chrome (Work)")]
        );
    }

    #[test]
    fn stale_events_after_sleep_are_ignored() {
        let mut w = Watch::default();
        assert!(w.poll(at(1_000).block(1, "Work").build(), &on()).is_empty());
        // The GUI slept: the daemon logged a kill long ago and one just now.
        let woke = at(10_000)
            .block(1, "Work")
            .event(1, 10_000 - 121, EventKind::AppKill, 1, "old")
            .event(2, 10_000 - 120, EventKind::AppKill, 1, "fresh")
            .build();
        assert_eq!(
            pairs(&w.poll(woke, &on())),
            vec![("App closed", "GrepFocus closed fresh (Work)")]
        );
        // The stale entry was accounted for, not deferred.
        let again = at(10_005)
            .block(1, "Work")
            .event(1, 10_000 - 121, EventKind::AppKill, 1, "old")
            .event(2, 10_000 - 120, EventKind::AppKill, 1, "fresh")
            .build();
        assert!(w.poll(again, &on()).is_empty());
    }

    #[test]
    fn notifications_off_advances_every_baseline() {
        let mut w = Watch::default();
        let before = at(1_000)
            .block(1, "Work")
            .block(2, "Social")
            .on_break(2, 1_100)
            .pomodoro_block(7, "Deep")
            .pomodoro(7, PomodoroPhase::Focus, 1_004, 3, 4)
            .build();
        assert!(w.poll(before, &nudges()).is_empty());

        // With notifications off, everything happens at once: a block ends,
        // one starts, a break crosses its one-minute edge, the pomodoro set
        // completes (its block lingers), events arrive, enforcement goes RED.
        let during = at(1_045)
            .block(2, "Social")
            .on_break(2, 1_100)
            .block(3, "Games")
            .pomodoro_block(7, "Deep")
            .health(hosts_error())
            .event(1, 1_044, EventKind::AppKill, 3, "steam")
            .event(2, 1_044, EventKind::Attempt, 2, "reddit.com")
            .build();
        assert!(w.poll(during, &off()).is_empty());

        // Back on with the same state: nothing is replayed — not the start,
        // not the end, not the warning, not the events, not the fault.
        let same = at(1_050)
            .block(2, "Social")
            .on_break(2, 1_100)
            .block(3, "Games")
            .pomodoro_block(7, "Deep")
            .health(hosts_error())
            .event(1, 1_044, EventKind::AppKill, 3, "steam")
            .event(2, 1_044, EventKind::Attempt, 2, "reddit.com")
            .build();
        assert!(w.poll(same, &nudges()).is_empty());

        // The completion seen while off still suppresses the block's end,
        // and the break that ended is still a "Break over" because that
        // edge is new.
        let after = at(1_101)
            .block(2, "Social")
            .block(3, "Games")
            .health(hosts_error())
            .event(1, 1_044, EventKind::AppKill, 3, "steam")
            .event(2, 1_044, EventKind::Attempt, 2, "reddit.com")
            .build();
        assert_eq!(
            pairs(&w.poll(after, &nudges())),
            vec![("Break over", "Social is blocked again")]
        );

        // Rate limits only count what was shown: the kill seen while off
        // does not silence the next one.
        let kill_again = at(1_106)
            .block(2, "Social")
            .block(3, "Games")
            .health(hosts_error())
            .event(3, 1_105, EventKind::AppKill, 3, "steam")
            .build();
        assert_eq!(
            pairs(&w.poll(kill_again, &nudges())),
            vec![("App closed", "GrepFocus closed steam (Games)")]
        );
    }

    #[test]
    fn red_edge_unchanged() {
        let mut w = Watch::default();
        assert!(w.poll(at(1_000).block(1, "Work").build(), &on()).is_empty());
        // Healthy → hosts error: the edge notifies, once.
        let red = w.poll(
            at(1_005).block(1, "Work").health(hosts_error()).build(),
            &on(),
        );
        assert_eq!(titles(&red), vec!["GrepFocus: blocking problem"]);
        assert!(red[0].body.contains("/etc/hosts"));
        assert!(w
            .poll(
                at(1_010).block(1, "Work").health(hosts_error()).build(),
                &on()
            )
            .is_empty());
        // Clearing is silent; a fresh fault is a fresh edge.
        assert!(w.poll(at(1_015).block(1, "Work").build(), &on()).is_empty());
        assert_eq!(
            titles(&w.poll(
                at(1_020).block(1, "Work").health(hosts_error()).build(),
                &on()
            )),
            vec!["GrepFocus: blocking problem"]
        );

        // nft Failed is RED only while a domain block is active: with no
        // block it is nothing, and the block starting is the edge.
        let mut w = Watch::default();
        assert!(w.poll(at(2_000).build(), &on()).is_empty());
        assert!(w
            .poll(at(2_005).health(nft_failed()).build(), &on())
            .is_empty());
        let red = w.poll(
            at(2_010).block(1, "Work").health(nft_failed()).build(),
            &on(),
        );
        assert_eq!(
            titles(&red),
            vec!["Block started", "GrepFocus: blocking problem"]
        );
        assert!(red[1].body.contains("DoH"));
    }

    #[test]
    fn enforcement_red_mirrors_frontend_rules() {
        // A daemon too old to report says nothing, whatever the fields hold.
        let old = Health {
            last_error: Some("hosts: read-only file system".to_string()),
            ..Health::default()
        };
        assert_eq!(enforcement_red(&old, true), None);

        // last_error is RED with or without a domain block.
        let hosts = Health {
            last_error: Some("hosts: read-only file system".to_string()),
            ..reporting()
        };
        assert!(enforcement_red(&hosts, true).is_some());
        assert!(enforcement_red(&hosts, false).is_some());

        // nft Failed is RED only while a domain block is active.
        let nft = Health {
            nft: NftStatus::Failed {
                reason: "nft: command not found".to_string(),
            },
            ..reporting()
        };
        assert!(enforcement_red(&nft, true).is_some());
        assert_eq!(enforcement_red(&nft, false), None);

        // StaleTable is the banner's YELLOW, never a notification.
        let stale = Health {
            nft: NftStatus::StaleTable {
                reason: "table busy".to_string(),
            },
            ..reporting()
        };
        assert_eq!(enforcement_red(&stale, true), None);
        assert_eq!(enforcement_red(&reporting(), true), None);
    }

    #[test]
    fn ordinals_read_right() {
        let cases = [
            (1, "st"),
            (2, "nd"),
            (3, "rd"),
            (4, "th"),
            (11, "th"),
            (12, "th"),
            (13, "th"),
            (21, "st"),
            (22, "nd"),
            (23, "rd"),
            (101, "st"),
            (111, "th"),
            (112, "th"),
        ];
        for (n, want) in cases {
            assert_eq!(ordinal(n), want, "{n}");
        }
    }
}
