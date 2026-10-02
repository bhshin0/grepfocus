//! The daemon's trusted time base for block timing.
//!
//! Every decision about when a block, a break or a pomodoro phase ends reads
//! this clock (`Daemon::now`), never the wall clock directly, so that stepping
//! the system clock during a block cannot shorten it. `date -s` needs root,
//! so this is friction against sudo-in-the-moment — the same stance as the
//! README's *Known limits*. (The unit's `ProtectClock=yes` is unrelated: it
//! sandboxes the daemon's own process, and does nothing against a root
//! shell's `date -s`.)
//!
//! The idea: per tick, compare how far the wall clock moved with how far
//! `CLOCK_BOOTTIME` moved. `CLOCK_BOOTTIME` is monotonic and — unlike
//! `CLOCK_MONOTONIC`, which an `Instant` reads — keeps counting through
//! suspend, so the two deltas agree exactly whenever timekeeping was honest,
//! sleep included, and disagree exactly when the clock was stepped.
//!
//! * Deltas agree (within [`STEP_TOLERANCE_SECS`]) → trusted time follows the
//!   wall clock. NTP slew and leap seconds are absorbed, but only up to the
//!   tolerance per busy stretch: a chain of small steps, each inside the
//!   tolerance, cannot drive trusted time ahead of elapsed time by more
//!   than 2 s in total before the next idle resync.
//! * Deltas disagree → trusted time advances by the elapsed (BOOTTIME) delta
//!   only, and the step is reported once. A forward step during a block
//!   therefore makes the block end LATER in real time, never earlier; a
//!   backward step changes nothing.
//! * Idle (nothing active, no pomodoro) → trusted time resyncs to the wall
//!   clock in both directions, and the absorbed-drift budget is handed
//!   back. Nothing is at stake while idle, and the frame is what the status
//!   frame, the event stamps and the attempt windows are read in, so a step
//!   seen while idle must not leave trusted time permanently offset from
//!   the wall clock the rest of the system keeps. While anything runs,
//!   trusted time never resyncs. Schedules fire by wall time regardless,
//!   and the block they start ends on this clock: its `ends_at_unix` is
//!   trusted time at the fire plus the window's remaining length, never
//!   the wall instant the window ends at, so the two frames may diverge
//!   while a block runs without a fire expiring on the spot.
//!
//! Restart continuity: the scheduler persists a [`ClockAnchor`] (trusted
//! time, the BOOTTIME reading it was taken at, the kernel's `boot_id`, and
//! the drift absorbed so far in this busy stretch) on every save. A daemon
//! that starts within the same boot resumes from it exactly — trusted time
//! plus the BOOTTIME elapsed since, with the absorbed budget still spent —
//! however stale the save, so "step the clock, kill -9, let systemd
//! restart" does not work either, and neither does "step by the tolerance,
//! save, restart" in a loop. After a reboot the anchor is stale by
//! construction and the clock seeds from the wall clock, clamped to
//! `high_water_unix`; changing the clock across a reboot is root with
//! physical access, out of scope.
//!
//! The clock is a leaf `std::sync::Mutex` on `Daemon` — taken for
//! microseconds, never across an await, like `health` — so the scheduler
//! can advance it with `state` held and the proxy's accept path can stamp
//! an attempt with it. Everything but `read` and `boot_id` is pure.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use grepfocus_core::{now_unix, ClockAnchor};
use tracing::warn;

/// Largest disagreement between the wall-clock and BOOTTIME deltas of one
/// tick that still counts as honest timekeeping (NTP slew, a leap second,
/// scheduling jitter), and the most drift one busy stretch absorbs in total.
pub const STEP_TOLERANCE_SECS: u64 = 2;

/// One simultaneous reading of both clocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Readings {
    /// `SystemTime`, unix seconds.
    pub wall_unix: u64,
    /// `CLOCK_BOOTTIME`, seconds since boot including suspend.
    pub boot_secs: u64,
}

static BOOTTIME_WARNED: AtomicBool = AtomicBool::new(false);

/// Read both clocks now. Should `CLOCK_BOOTTIME` ever be unavailable, the
/// wall clock stands in for it (logged once): the deltas then always agree
/// and block timing follows the wall clock, the pre-guard behaviour.
pub fn read() -> Readings {
    let wall_unix = now_unix();
    let boot_secs = match nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME) {
        Ok(ts) => ts.tv_sec().max(0) as u64,
        Err(err) => {
            if !BOOTTIME_WARNED.swap(true, Ordering::Relaxed) {
                warn!(%err, "CLOCK_BOOTTIME unavailable; block timing follows the wall clock");
            }
            wall_unix
        }
    };
    Readings {
        wall_unix,
        boot_secs,
    }
}

/// The kernel's boot identity, `/proc/sys/kernel/random/boot_id`, trimmed.
/// Empty when unreadable — and an empty id never matches an anchor.
pub fn boot_id() -> String {
    match std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
        Ok(s) => s.trim().to_string(),
        Err(err) => {
            warn!(%err, "boot_id unreadable; the block clock will not survive a restart");
            String::new()
        }
    }
}

/// What one tick's `advance` saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// The wall clock and BOOTTIME advanced together; trusted time followed
    /// the wall clock.
    Tracked,
    /// The wall clock moved by `secs` more (positive) or less (negative)
    /// than real time elapsed; trusted time advanced by the elapsed time.
    Jumped { secs: i64 },
}

/// The trusted block clock. See the module docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockClock {
    /// Trusted time as of the last tick.
    trusted_unix: u64,
    /// The readings of the last tick.
    last_wall_unix: u64,
    last_boot_secs: u64,
    /// Wall-vs-BOOTTIME drift absorbed into trusted time since the last
    /// resync, in `-TOL..=TOL`. Bounds what a chain of in-tolerance steps
    /// can add; reset whenever the clock resyncs to the wall clock.
    absorbed_secs: i64,
}

impl BlockClock {
    /// Start from the wall clock, no earlier than `floor` (the persisted
    /// `high_water_unix`): a clock rolled back while the daemon was down
    /// cannot start trusted time in the past.
    pub fn seed(r: Readings, floor: u64) -> Self {
        BlockClock {
            trusted_unix: r.wall_unix.max(floor),
            last_wall_unix: r.wall_unix,
            last_boot_secs: r.boot_secs,
            absorbed_secs: 0,
        }
    }

    /// Rebuild the clock at startup. With an anchor from this very boot
    /// (`boot_id` equal and non-empty) trusted time is the anchor's plus the
    /// BOOTTIME elapsed since it was taken — exact, whatever the wall clock
    /// did meanwhile — and the absorbed-drift budget is the anchor's, clamped
    /// to the tolerance (a restart is not an idle resync: it hands nothing
    /// back); otherwise `seed`. The flag says which happened.
    pub fn resume(
        anchor: Option<&ClockAnchor>,
        boot_id: &str,
        r: Readings,
        floor: u64,
    ) -> (Self, bool) {
        match anchor {
            Some(a) if !boot_id.is_empty() && a.boot_id == boot_id => {
                let elapsed = r.boot_secs.saturating_sub(a.boot_secs);
                let tolerance = STEP_TOLERANCE_SECS as i64;
                let clock = BlockClock {
                    trusted_unix: a.trusted_unix.saturating_add(elapsed),
                    last_wall_unix: r.wall_unix,
                    last_boot_secs: r.boot_secs,
                    absorbed_secs: a.absorbed_secs.clamp(-tolerance, tolerance),
                };
                (clock, true)
            }
            _ => (Self::seed(r, floor), false),
        }
    }

    /// Advance to the readings of this tick. `idle` is "nothing active and
    /// no pomodoro": then trusted time resyncs to the wall clock after the
    /// step check, in either direction. Pure.
    pub fn advance(&mut self, r: Readings, idle: bool) -> Step {
        let wall_delta = r.wall_unix as i64 - self.last_wall_unix as i64;
        let boot_delta = r.boot_secs.saturating_sub(self.last_boot_secs);
        let divergence = wall_delta - boot_delta as i64;
        let tolerance = STEP_TOLERANCE_SECS as i64;
        let step = if divergence.abs() <= tolerance {
            // Honest: follow the wall clock, but absorb its drift from
            // elapsed time only up to the tolerance per busy stretch.
            let absorbed = (self.absorbed_secs + divergence).clamp(-tolerance, tolerance);
            let follow = boot_delta as i64 + (absorbed - self.absorbed_secs);
            self.absorbed_secs = absorbed;
            self.trusted_unix = (self.trusted_unix as i64 + follow).max(0) as u64;
            Step::Tracked
        } else {
            self.trusted_unix = self.trusted_unix.saturating_add(boot_delta);
            Step::Jumped { secs: divergence }
        };
        if idle {
            self.trusted_unix = r.wall_unix;
            self.absorbed_secs = 0;
        }
        self.last_wall_unix = r.wall_unix;
        self.last_boot_secs = r.boot_secs;
        step
    }

    /// Trusted time at readings `r` taken after the last tick: the tick's
    /// trusted time plus the BOOTTIME elapsed since, so a reading between
    /// two ticks is exact rather than up to a second stale.
    pub fn now_at(&self, r: Readings) -> u64 {
        self.trusted_unix
            .saturating_add(r.boot_secs.saturating_sub(self.last_boot_secs))
    }

    /// What to persist so a restart within this boot can `resume`.
    pub fn anchor(&self, boot_id: &str) -> ClockAnchor {
        ClockAnchor {
            trusted_unix: self.trusted_unix,
            boot_secs: self.last_boot_secs,
            boot_id: boot_id.to_string(),
            absorbed_secs: self.absorbed_secs,
        }
    }
}

/// Trusted "now" through the daemon's clock lock: read the clocks, then take
/// the leaf lock for microseconds. Poison is recovered as for `health`.
pub fn now_in(clock: &Mutex<BlockClock>) -> u64 {
    let r = read();
    clock.lock().unwrap_or_else(|p| p.into_inner()).now_at(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WALL: u64 = 1_752_192_000;
    const BOOT: u64 = 5_000;

    fn r(wall_unix: u64, boot_secs: u64) -> Readings {
        Readings {
            wall_unix,
            boot_secs,
        }
    }

    fn busy_clock() -> BlockClock {
        BlockClock::seed(r(WALL, BOOT), 0)
    }

    #[test]
    fn seed_takes_the_wall_clock_clamped_to_the_floor() {
        assert_eq!(
            BlockClock::seed(r(WALL, BOOT), 0).now_at(r(WALL, BOOT)),
            WALL
        );
        // A clock rolled back while the daemon was down: the high-water mark
        // wins, exactly as it does for license expiry.
        let floor = WALL + 10_000;
        assert_eq!(
            BlockClock::seed(r(WALL, BOOT), floor).now_at(r(WALL, BOOT)),
            floor
        );
    }

    #[test]
    fn tracks_wall_when_deltas_agree() {
        let mut c = busy_clock();
        assert_eq!(c.advance(r(WALL + 1, BOOT + 1), false), Step::Tracked);
        assert_eq!(c.now_at(r(WALL + 1, BOOT + 1)), WALL + 1);
        // A tick that took two seconds (a stalled runtime) is still honest.
        assert_eq!(c.advance(r(WALL + 3, BOOT + 3), false), Step::Tracked);
        assert_eq!(c.now_at(r(WALL + 3, BOOT + 3)), WALL + 3);
    }

    #[test]
    fn suspend_counts_as_elapsed() {
        // Two hours asleep: both clocks moved two hours, so the block clock
        // did too — a block ends at its wall-clock end, or on the first tick
        // after resume if that has passed.
        let mut c = busy_clock();
        assert_eq!(
            c.advance(r(WALL + 7_200, BOOT + 7_200), false),
            Step::Tracked
        );
        assert_eq!(c.now_at(r(WALL + 7_200, BOOT + 7_200)), WALL + 7_200);
    }

    #[test]
    fn forward_step_while_busy_advances_by_elapsed_only() {
        // `date -s '+5 hours'` between two ticks: one second really passed.
        let mut c = busy_clock();
        assert_eq!(
            c.advance(r(WALL + 18_000, BOOT + 1), false),
            Step::Jumped { secs: 17_999 }
        );
        assert_eq!(c.now_at(r(WALL + 18_000, BOOT + 1)), WALL + 1);
    }

    #[test]
    fn backward_step_while_busy_keeps_advancing() {
        let mut c = busy_clock();
        assert_eq!(
            c.advance(r(WALL - 7_200, BOOT + 1), false),
            Step::Jumped { secs: -7_201 }
        );
        assert_eq!(c.now_at(r(WALL - 7_200, BOOT + 1)), WALL + 1);
        // And the next honest tick tracks the (now lagging) wall clock's
        // delta, not its value: still elapsed time.
        assert_eq!(c.advance(r(WALL - 7_199, BOOT + 2), false), Step::Tracked);
        assert_eq!(c.now_at(r(WALL - 7_199, BOOT + 2)), WALL + 2);
    }

    #[test]
    fn idle_resyncs_to_wall_both_directions() {
        // Forward step while idle: trusted time jumps up to the wall clock.
        let mut c = busy_clock();
        assert_eq!(
            c.advance(r(WALL + 18_000, BOOT + 1), true),
            Step::Jumped { secs: 17_999 }
        );
        assert_eq!(c.now_at(r(WALL + 18_000, BOOT + 1)), WALL + 18_000);
        // Backward step while idle: it comes back down. Without this, a
        // forward-then-back pair while idle would leave trusted time ahead
        // and expire the next scheduled block immediately.
        assert_eq!(
            c.advance(r(WALL + 2, BOOT + 2), true),
            Step::Jumped { secs: -17_999 }
        );
        assert_eq!(c.now_at(r(WALL + 2, BOOT + 2)), WALL + 2);
    }

    #[test]
    fn busy_never_resyncs_across_ticks() {
        // A forward step during a block is never caught up on while the
        // block runs: a hundred honest ticks later trusted time still lags
        // the wall clock by the whole step.
        let mut c = busy_clock();
        c.advance(r(WALL + 18_000, BOOT + 1), false);
        for i in 2..=101 {
            assert_eq!(
                c.advance(r(WALL + 18_000 + i - 1, BOOT + i), false),
                Step::Tracked
            );
        }
        assert_eq!(c.now_at(r(WALL + 18_100, BOOT + 101)), WALL + 101);
    }

    #[test]
    fn tolerance_boundary_is_two_seconds() {
        // Two seconds of disagreement is slew: followed.
        let mut c = busy_clock();
        assert_eq!(c.advance(r(WALL + 3, BOOT + 1), false), Step::Tracked);
        assert_eq!(c.now_at(r(WALL + 3, BOOT + 1)), WALL + 3);
        // Three is a step: elapsed time only.
        let mut c = busy_clock();
        assert_eq!(
            c.advance(r(WALL + 4, BOOT + 1), false),
            Step::Jumped { secs: 3 }
        );
        assert_eq!(c.now_at(r(WALL + 4, BOOT + 1)), WALL + 1);
        // Symmetric on the backward side.
        let mut c = busy_clock();
        assert_eq!(c.advance(r(WALL - 1, BOOT + 1), false), Step::Tracked);
        assert_eq!(c.now_at(r(WALL - 1, BOOT + 1)), WALL - 1);
        let mut c = busy_clock();
        assert_eq!(
            c.advance(r(WALL - 2, BOOT + 1), false),
            Step::Jumped { secs: -3 }
        );
    }

    #[test]
    fn small_steps_cannot_outrun_elapsed_time_by_more_than_the_tolerance() {
        // `date -s '+2 sec'` once a second, each step inside the tolerance:
        // the first absorbs, the rest are elapsed time only, so a block
        // still runs its real length (give or take the 2 s).
        let mut c = busy_clock();
        for i in 1..=600u64 {
            assert_eq!(c.advance(r(WALL + 3 * i, BOOT + i), false), Step::Tracked);
        }
        assert_eq!(c.now_at(r(WALL + 1_800, BOOT + 600)), WALL + 600 + 2);
        // The budget is per busy stretch: an idle resync hands it back.
        c.advance(r(WALL + 1_801, BOOT + 601), true);
        assert_eq!(c.advance(r(WALL + 1_804, BOOT + 602), false), Step::Tracked);
        assert_eq!(c.now_at(r(WALL + 1_804, BOOT + 602)), WALL + 1_804);
        // And slew in the other direction is bounded the same way.
        let mut c = busy_clock();
        for i in 1..=600u64 {
            c.advance(r(WALL, BOOT + i), false); // the wall clock stands still
        }
        assert_eq!(c.now_at(r(WALL, BOOT + 600)), WALL + 600 - 2);
    }

    #[test]
    fn resume_same_boot_adds_boot_elapsed() {
        // Anchored at trusted 5000 / BOOTTIME 100; the daemon comes back 60 s
        // of BOOTTIME later with a wall clock that was stepped meanwhile.
        let anchor = ClockAnchor {
            trusted_unix: 5_000,
            boot_secs: 100,
            boot_id: "0f7e5e9a-2b1c-4d3e-8f90-1a2b3c4d5e6f".into(),
            absorbed_secs: 0,
        };
        let (c, restored) = BlockClock::resume(
            Some(&anchor),
            "0f7e5e9a-2b1c-4d3e-8f90-1a2b3c4d5e6f",
            r(99_999_999, 160),
            0,
        );
        assert!(restored);
        assert_eq!(c.now_at(r(99_999_999, 160)), 5_060);
        // The stale-save case: however long the anchor sat unsaved, elapsed
        // BOOTTIME closes the gap exactly.
        let (c, _) = BlockClock::resume(Some(&anchor), &anchor.boot_id, r(1, 86_500), 0);
        assert_eq!(c.now_at(r(1, 86_500)), 5_000 + 86_400);
    }

    #[test]
    fn resume_other_boot_seeds_from_wall_clamped_to_high_water() {
        let anchor = ClockAnchor {
            trusted_unix: 5_000,
            boot_secs: 100,
            boot_id: "previous-boot".into(),
            absorbed_secs: 0,
        };
        let (c, restored) = BlockClock::resume(Some(&anchor), "this-boot", r(WALL, BOOT), 0);
        assert!(!restored);
        assert_eq!(c.now_at(r(WALL, BOOT)), WALL);
        // Rolled back across the reboot: the high-water mark wins.
        let (c, _) = BlockClock::resume(Some(&anchor), "this-boot", r(WALL, BOOT), WALL + 50);
        assert_eq!(c.now_at(r(WALL, BOOT)), WALL + 50);
        // No anchor at all (first run, or a pre-0.7.0 state file).
        let (c, restored) = BlockClock::resume(None, "this-boot", r(WALL, BOOT), 0);
        assert!(!restored);
        assert_eq!(c.now_at(r(WALL, BOOT)), WALL);
        // An unreadable boot_id (empty) never matches, not even an anchor
        // written by a daemon that could not read it either.
        let blank = ClockAnchor {
            boot_id: String::new(),
            ..anchor
        };
        let (_, restored) = BlockClock::resume(Some(&blank), "", r(WALL, BOOT), 0);
        assert!(!restored);
    }

    #[test]
    fn now_at_adds_boot_elapsed_between_ticks() {
        let mut c = busy_clock();
        c.advance(r(WALL + 1, BOOT + 1), false);
        // 400 ms into the next tick the BOOTTIME seconds may already have
        // rolled over; a mid-tick read is the tick's value plus that.
        assert_eq!(c.now_at(r(WALL + 1, BOOT + 1)), WALL + 1);
        assert_eq!(c.now_at(r(WALL + 2, BOOT + 2)), WALL + 2);
        // ... and the wall clock does not enter into it at all.
        assert_eq!(c.now_at(r(WALL + 9_999, BOOT + 2)), WALL + 2);
    }

    #[test]
    fn anchor_carries_the_tick_and_the_boot_id() {
        let mut c = busy_clock();
        c.advance(r(WALL + 18_000, BOOT + 1), false); // a step: trusted = WALL + 1
        assert_eq!(
            c.anchor("boot-x"),
            ClockAnchor {
                trusted_unix: WALL + 1,
                boot_secs: BOOT + 1,
                boot_id: "boot-x".into(),
                absorbed_secs: 0,
            }
        );
        // Round trip through resume in the same boot: the next daemon
        // continues where this one stood.
        let (back, restored) = BlockClock::resume(
            Some(&c.anchor("boot-x")),
            "boot-x",
            r(WALL + 18_010, BOOT + 11),
            0,
        );
        assert!(restored);
        assert_eq!(back.now_at(r(WALL + 18_010, BOOT + 11)), WALL + 11);
    }

    #[test]
    fn resume_same_boot_keeps_the_absorbed_budget() {
        // One in-tolerance step while busy spends the whole budget: trusted
        // time is two seconds ahead of elapsed time.
        let mut c = busy_clock();
        assert_eq!(c.advance(r(WALL + 3, BOOT + 1), false), Step::Tracked);
        assert_eq!(c.now_at(r(WALL + 3, BOOT + 1)), WALL + 3);
        let anchor = c.anchor("boot-x");
        assert_eq!(anchor.absorbed_secs, 2);
        // "Save, restart" within the same boot: the budget comes back spent,
        // so the next in-tolerance step is elapsed time only. Without this
        // the loop "step +2 s, save, restart" would gain 2 s per lap — a
        // 3600 s block was observed expiring after 1200 s.
        let (mut back, restored) =
            BlockClock::resume(Some(&anchor), "boot-x", r(WALL + 3, BOOT + 1), 0);
        assert!(restored);
        assert_eq!(back.advance(r(WALL + 6, BOOT + 2), false), Step::Tracked);
        assert_eq!(back.now_at(r(WALL + 6, BOOT + 2)), WALL + 3 + 1);
        // Many laps later it is still the one-off 2 s over elapsed time.
        let mut c = back;
        for i in 3..=50u64 {
            let (next, _) = BlockClock::resume(
                Some(&c.anchor("boot-x")),
                "boot-x",
                r(WALL + 3 * (i - 1), BOOT + i - 1),
                0,
            );
            c = next;
            assert_eq!(c.advance(r(WALL + 3 * i, BOOT + i), false), Step::Tracked);
        }
        assert_eq!(c.now_at(r(WALL + 150, BOOT + 50)), WALL + 50 + 2);
        // The persisted value is clamped on the way in, so a state file
        // claiming more budget than the tolerance restores at most the
        // tolerance — in either direction.
        let generous = ClockAnchor {
            absorbed_secs: 99,
            ..c.anchor("boot-x")
        };
        let (g, _) = BlockClock::resume(Some(&generous), "boot-x", r(WALL + 150, BOOT + 50), 0);
        assert_eq!(g.absorbed_secs, STEP_TOLERANCE_SECS as i64);
        let stingy = ClockAnchor {
            absorbed_secs: -99,
            ..c.anchor("boot-x")
        };
        let (s, _) = BlockClock::resume(Some(&stingy), "boot-x", r(WALL + 150, BOOT + 50), 0);
        assert_eq!(s.absorbed_secs, -(STEP_TOLERANCE_SECS as i64));
    }

    // Live readings: the one place the real clocks are consulted in tests.
    #[test]
    fn read_returns_the_live_clocks() {
        let before = now_unix();
        let a = read();
        let b = read();
        let after = now_unix();
        assert!((before..=after).contains(&a.wall_unix));
        assert!(
            a.boot_secs > 0,
            "CLOCK_BOOTTIME reads as seconds since boot"
        );
        assert!(b.boot_secs >= a.boot_secs, "BOOTTIME is monotonic");
        assert!(
            a.boot_secs < a.wall_unix,
            "seconds since boot, not since 1970"
        );
    }

    #[test]
    fn boot_id_is_the_kernel_uuid() {
        let id = boot_id();
        assert_eq!(id.len(), 36, "got {id:?}");
        assert_eq!(id.matches('-').count(), 4, "got {id:?}");
        assert_eq!(boot_id(), id, "stable within a boot");
    }
}
