//! Reconciles `state.active` against (a) wall-clock expiry and (b) recurring
//! `state.schedules`. Runs once per second.
//!
//! Three jobs per tick, performed under a single state lock:
//! 1. Drop any active blocks whose `ends_at_unix <= now`.
//! 2. Drop any *schedule-originated* active blocks whose driving schedule
//!    has been disabled/deleted or has slid outside its time window.
//! 3. Start any enabled schedule that is currently in its window and not
//!    already represented in `state.active`.
//!
//! After mutating, persist the new state and (if anything changed)
//! recompute the hosts file outside the lock.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Datelike, Local, NaiveDate, TimeZone, Timelike};
use grepfocus_core::license::features;
use grepfocus_core::{day_set, now_unix, ActiveBlock, Originator, Schedule, State};
use tracing::{error, info, warn};

use crate::{enforce, has_feature, state, Daemon};

const TICK: Duration = Duration::from_secs(1);

/// License-derived permissions for one reconcile pass. Computed by `tick`
/// from the daemon's cached license claims (via `crate::has_feature`) and
/// threaded into `reconcile` as plain data, so reconcile stays pure —
/// clock-free, IO-free, unit-testable.
pub struct Gates {
    /// `schedules` feature: may a schedule window CREATE a new active record
    /// this pass? Already-running actives are never touched by this gate —
    /// an in-flight window always runs to completion.
    pub schedules: bool,
    /// `app_blocking` feature: snapshotted into `ActiveBlock::apps_enforced`
    /// on any record created this pass (a mid-block license change must
    /// never alter a running block's app enforcement).
    pub app_blocking: bool,
}

pub async fn run(daemon: Arc<Daemon>) {
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // `(schedule_id, window_end_unix)` pairs whose fire was skipped for lack
    // of a license and has already been logged. Keyed on the window's end so
    // each *occurrence* of a weekly window logs exactly once, not once per 1s
    // tick; reconcile prunes entries once their window has passed.
    let mut skipped_fires: HashSet<(u64, u64)> = HashSet::new();
    loop {
        ticker.tick().await;
        tick(&daemon, &mut skipped_fires).await;
    }
}

async fn tick(daemon: &Arc<Daemon>, skipped_fires: &mut HashSet<(u64, u64)>) {
    let now_unix = now_unix();
    let now_local = Local::now();
    let today = now_local.date_naive().num_days_from_ce() as i64;

    {
        let mut st = daemon.state.lock().await;
        // Track the highest time ever observed (clock-rollback guard for
        // license expiry — see `crate::effective_now`). Deliberately bumped
        // in-memory only: an fsync every second is unacceptable disk churn,
        // so the mark persists opportunistically whenever anything else
        // saves. Accepted trade-off: after a crash the stored mark lags by
        // however long the state went unsaved, so a rollback attacker gains
        // at most that window.
        if now_unix > st.high_water_unix {
            st.high_water_unix = now_unix;
        }
        let gates = {
            let lic = daemon.license.lock().await;
            Gates {
                schedules: has_feature(lic.as_ref(), &st, features::SCHEDULES),
                app_blocking: has_feature(lic.as_ref(), &st, features::APP_BLOCKING),
            }
        };
        if reconcile(&mut st, now_unix, &now_local, today, &gates, skipped_fires) {
            if let Err(e) = state::save(&st, &daemon.key) {
                error!(?e, "scheduler save failed");
            }
        }
    }

    // Reconcile enforcement every tick: sync() is a no-op while the applied
    // union is unchanged, and retries automatically after a failed apply.
    if let Err(e) = enforce::sync(daemon).await {
        error!(?e, "scheduler enforce sync failed");
    }
}

/// Bring `st.active` into agreement with wall-clock expiry and the schedule
/// table, and prune stale allowance-ledger entries. Pure over its inputs (no
/// clock, no IO) so it can be unit-tested. Returns whether anything changed and
/// the state therefore needs persisting.
///
/// Steps, in order:
/// 1. Drop actives whose `ends_at_unix <= now_unix`.
/// 2. Drop schedule-originated actives whose schedule was disabled/deleted or
///    slid out of its window.
/// 3. Start any enabled schedule currently in-window and not already active —
///    unless `gates.schedules` is off, in which case the fire is skipped (and
///    logged once per window via `skipped_fires`). New actives snapshot
///    `gates.app_blocking` into `apps_enforced`.
/// 4. Clear breaks that have elapsed (enforcement resumes).
///
/// It also prunes allowance-ledger rows from days other than `today`, and
/// `skipped_fires` entries whose window has passed.
fn reconcile(
    st: &mut State,
    now_unix: u64,
    now_local: &DateTime<Local>,
    today: i64,
    gates: &Gates,
    skipped_fires: &mut HashSet<(u64, u64)>,
) -> bool {
    // Snapshot schedules so we can iterate them while mutating st.active.
    let schedules: Vec<Schedule> = st.schedules.clone();
    let mut changed = false;

    // 1. Expire by wall clock.
    let before = st.active.len();
    st.active.retain(|a| a.ends_at_unix > now_unix);
    let expired = before - st.active.len();
    if expired > 0 {
        info!(count = expired, "expired active blocks");
        changed = true;
    }

    // 2. End scheduled actives whose driving schedule disappeared,
    //    was disabled, or slid out of its window.
    let before = st.active.len();
    st.active.retain(|a| match &a.originator {
        Originator::Manual => true,
        Originator::Schedule { schedule_id } => schedules
            .iter()
            .find(|s| s.id == *schedule_id)
            .map(|s| s.enabled && schedule_active_at(s, now_local))
            .unwrap_or(false),
    });
    let auto_ended = before - st.active.len();
    if auto_ended > 0 {
        info!(count = auto_ended, "ended schedule-driven blocks");
        changed = true;
    }

    // 3. Auto-start schedules whose window is now open.
    //
    // Drop skip-log markers for windows that have passed first, so the set
    // can't grow across weeks of unlicensed uptime.
    skipped_fires.retain(|&(_, window_end)| window_end > now_unix);
    for s in &schedules {
        if !s.enabled || !schedule_active_at(s, now_local) {
            continue;
        }
        // One ActiveBlock per block, no matter who started it: a manual
        // run or another schedule already enforcing this block means
        // there is nothing to add. (Two entries for one block would let
        // TakeBreak pause one while the other keeps enforcing.)
        let already_active = st.active.iter().any(|a| a.block.id == s.block_id);
        if already_active {
            continue;
        }
        if !gates.schedules {
            // Fire-time license gate: without the `schedules` feature a
            // window never CREATES a new active record. Existing actives
            // were already retained above untouched — an in-flight window
            // runs to completion; only new fires stop. Log once per window
            // occurrence (first tick the skip is seen), not once per tick.
            if skipped_fires.insert((s.id, compute_window_end_unix(s, now_local))) {
                info!(
                    schedule_id = s.id,
                    block_id = s.block_id,
                    "schedule fire skipped: schedules are a premium feature \
                     and no valid license is present"
                );
            }
            continue;
        }
        let block = match st.blocks.iter().find(|b| b.id == s.block_id) {
            Some(b) => b.clone(),
            None => {
                warn!(
                    schedule_id = s.id,
                    block_id = s.block_id,
                    "schedule references missing block"
                );
                continue;
            }
        };
        let ends_at_unix = compute_window_end_unix(s, now_local);
        st.active.push(ActiveBlock {
            block,
            started_at_unix: now_unix,
            ends_at_unix,
            originator: Originator::Schedule { schedule_id: s.id },
            break_until_unix: None,
            // Snapshotted at activation: a mid-block license change (either
            // direction) never alters a running block's app enforcement.
            apps_enforced: gates.app_blocking,
        });
        info!(
            schedule_id = s.id,
            block_id = s.block_id,
            "auto-started block from schedule"
        );
        changed = true;
    }

    // 4. Resume any block whose break has ended (enforcement returns).
    for a in st.active.iter_mut() {
        if a.break_until_unix.is_some_and(|t| t <= now_unix) {
            a.break_until_unix = None;
            info!(block_id = a.block.id, "break ended");
            changed = true;
        }
    }

    // Prune break-allowance ledger entries from previous days (resets the
    // daily allowance). This needs a save but not a re-apply on its own.
    let before = st.allowance.len();
    st.allowance.retain(|l| l.day == today);
    let ledger_pruned = st.allowance.len() != before;

    changed || ledger_pruned
}

/// Days since the Common-Era epoch in local time. The absolute value is
/// irrelevant — it only needs to change at local midnight so the break
/// allowance resets daily.
pub fn local_day() -> i64 {
    Local::now().date_naive().num_days_from_ce() as i64
}

/// True if `t` falls inside today's scheduled window.
fn schedule_active_at(s: &Schedule, t: &DateTime<Local>) -> bool {
    let weekday = t.weekday().num_days_from_sunday() as u8; // 0=Sun..6=Sat
    if !day_set(s.days, weekday) {
        return false;
    }
    let minute_of_day = t.hour() * 60 + t.minute();
    let start = s.start_minute as u32;
    let end = start + s.duration_minutes as u32;
    (start..end).contains(&minute_of_day)
}

/// The unix-time end of the schedule's current window. Assumes
/// `schedule_active_at(s, now)` is true (caller checks).
fn compute_window_end_unix(s: &Schedule, now: &DateTime<Local>) -> u64 {
    let end_minute = s.start_minute as u32 + s.duration_minutes as u32;
    let (date, h, m): (NaiveDate, u32, u32) = if end_minute >= 1440 {
        // End at midnight: that's 00:00 tomorrow.
        (now.date_naive() + chrono::Duration::days(1), 0, 0)
    } else {
        (now.date_naive(), end_minute / 60, end_minute % 60)
    };
    let naive = date.and_hms_opt(h, m, 0).expect("validated h/m");
    let end_local = Local
        .from_local_datetime(&naive)
        .single()
        .unwrap_or_else(|| *now + chrono::Duration::minutes(s.duration_minutes as i64));
    end_local.timestamp().max(0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use grepfocus_core::{AllowanceLedger, Block, DAY_MON};

    fn s(start: u16, dur: u16, days: u8) -> Schedule {
        Schedule {
            id: 1,
            name: "t".into(),
            block_id: 0,
            days,
            start_minute: start,
            duration_minutes: dur,
            enabled: true,
        }
    }

    fn t(h: u32, m: u32, weekday: chrono::Weekday) -> DateTime<Local> {
        let base = NaiveDate::from_ymd_opt(2026, 1, 5).unwrap(); // a Monday
        let delta = weekday.num_days_from_monday() as i64;
        let date = base + chrono::Duration::days(delta);
        Local
            .from_local_datetime(&date.and_hms_opt(h, m, 0).unwrap())
            .unwrap()
    }

    #[test]
    fn inside_window_on_correct_day() {
        let sch = s(540, 60, DAY_MON); // Mon 09:00–10:00
        assert!(schedule_active_at(&sch, &t(9, 30, chrono::Weekday::Mon)));
    }

    #[test]
    fn outside_window_same_day() {
        let sch = s(540, 60, DAY_MON);
        assert!(!schedule_active_at(&sch, &t(8, 59, chrono::Weekday::Mon)));
        assert!(!schedule_active_at(&sch, &t(10, 0, chrono::Weekday::Mon)));
    }

    #[test]
    fn wrong_weekday() {
        let sch = s(540, 60, DAY_MON);
        assert!(!schedule_active_at(&sch, &t(9, 30, chrono::Weekday::Tue)));
    }

    // ── reconcile() ─────────────────────────────────────────────────────────

    fn block(id: u64) -> Block {
        Block {
            id,
            name: format!("block-{id}"),
            domains: vec!["example.com".into()],
            apps: vec![],
            allowance_secs_per_day: 0,
        }
    }

    fn manual_active(block_id: u64, ends_at_unix: u64) -> ActiveBlock {
        ActiveBlock {
            block: block(block_id),
            started_at_unix: 0,
            ends_at_unix,
            originator: Originator::Manual,
            break_until_unix: None,
            apps_enforced: false,
        }
    }

    fn sched_active(block_id: u64, schedule_id: u64, ends_at_unix: u64) -> ActiveBlock {
        ActiveBlock {
            block: block(block_id),
            started_at_unix: 0,
            ends_at_unix,
            originator: Originator::Schedule { schedule_id },
            break_until_unix: None,
            apps_enforced: false,
        }
    }

    /// Everything licensed — preserves pre-gating behavior for the tests
    /// that aren't about licensing.
    fn all_gates() -> Gates {
        Gates {
            schedules: true,
            app_blocking: true,
        }
    }

    fn free_gates() -> Gates {
        Gates {
            schedules: false,
            app_blocking: false,
        }
    }

    fn unix(dt: &DateTime<Local>) -> u64 {
        dt.timestamp() as u64
    }

    fn day_of(dt: &DateTime<Local>) -> i64 {
        dt.date_naive().num_days_from_ce() as i64
    }

    #[test]
    fn expires_by_wall_clock() {
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let mut st = State::default();
        st.active.push(manual_active(0, now - 1)); // ended a second ago
        st.active.push(manual_active(1, now + 100)); // still live
        let changed = reconcile(
            &mut st,
            now,
            &now_l,
            day_of(&now_l),
            &all_gates(),
            &mut HashSet::new(),
        );
        assert!(changed);
        assert_eq!(st.active.len(), 1);
        assert_eq!(st.active[0].block.id, 1);
    }

    #[test]
    fn auto_starts_in_window_schedule() {
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let mut st = State::default();
        st.blocks.push(block(0));
        st.schedules.push(s(540, 60, DAY_MON)); // Mon 09:00–10:00, id 1, block 0
        let changed = reconcile(
            &mut st,
            now,
            &now_l,
            day_of(&now_l),
            &all_gates(),
            &mut HashSet::new(),
        );
        assert!(changed);
        assert_eq!(st.active.len(), 1);
        assert!(matches!(
            st.active[0].originator,
            Originator::Schedule { schedule_id: 1 }
        ));
    }

    #[test]
    fn does_not_duplicate_existing_manual_active() {
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let mut st = State::default();
        st.blocks.push(block(0));
        st.schedules.push(s(540, 60, DAY_MON));
        st.active.push(manual_active(0, now + 3600)); // manual already enforcing block 0
        let changed = reconcile(
            &mut st,
            now,
            &now_l,
            day_of(&now_l),
            &all_gates(),
            &mut HashSet::new(),
        );
        assert_eq!(st.active.len(), 1);
        assert!(matches!(st.active[0].originator, Originator::Manual));
        assert!(!changed);
    }

    #[test]
    fn ends_scheduled_active_when_disabled() {
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let mut st = State::default();
        st.blocks.push(block(0));
        let mut sch = s(540, 60, DAY_MON);
        sch.enabled = false;
        st.schedules.push(sch);
        st.active.push(sched_active(0, 1, now + 3600));
        let changed = reconcile(
            &mut st,
            now,
            &now_l,
            day_of(&now_l),
            &all_gates(),
            &mut HashSet::new(),
        );
        assert!(changed);
        assert!(st.active.is_empty());
    }

    #[test]
    fn ends_scheduled_active_when_window_slides() {
        let now_l = t(10, 30, chrono::Weekday::Mon); // past the 09:00–10:00 window
        let now = unix(&now_l);
        let mut st = State::default();
        st.blocks.push(block(0));
        st.schedules.push(s(540, 60, DAY_MON));
        st.active.push(sched_active(0, 1, now + 3600));
        let changed = reconcile(
            &mut st,
            now,
            &now_l,
            day_of(&now_l),
            &all_gates(),
            &mut HashSet::new(),
        );
        assert!(changed);
        assert!(st.active.is_empty());
    }

    #[test]
    fn ends_scheduled_active_when_schedule_deleted() {
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let mut st = State::default();
        st.blocks.push(block(0));
        // No schedule with id 99 exists.
        st.active.push(sched_active(0, 99, now + 3600));
        let changed = reconcile(
            &mut st,
            now,
            &now_l,
            day_of(&now_l),
            &all_gates(),
            &mut HashSet::new(),
        );
        assert!(changed);
        assert!(st.active.is_empty());
    }

    #[test]
    fn resumes_after_break_ends() {
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let mut st = State::default();
        let mut ab = manual_active(0, now + 3600);
        ab.break_until_unix = Some(now - 5); // break already elapsed
        st.active.push(ab);
        let changed = reconcile(
            &mut st,
            now,
            &now_l,
            day_of(&now_l),
            &all_gates(),
            &mut HashSet::new(),
        );
        assert!(changed);
        assert!(st.active[0].break_until_unix.is_none());
    }

    #[test]
    fn keeps_ongoing_break() {
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let mut st = State::default();
        let mut ab = manual_active(0, now + 3600);
        ab.break_until_unix = Some(now + 30); // still on break
        st.active.push(ab);
        let changed = reconcile(
            &mut st,
            now,
            &now_l,
            day_of(&now_l),
            &all_gates(),
            &mut HashSet::new(),
        );
        assert!(!changed);
        assert_eq!(st.active[0].break_until_unix, Some(now + 30));
    }

    #[test]
    fn prunes_old_allowance_rows() {
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let today = day_of(&now_l);
        let mut st = State::default();
        st.allowance.push(AllowanceLedger {
            block_id: 0,
            day: today - 1,
            used_secs: 100,
        });
        st.allowance.push(AllowanceLedger {
            block_id: 0,
            day: today,
            used_secs: 50,
        });
        let changed = reconcile(
            &mut st,
            now,
            &now_l,
            today,
            &all_gates(),
            &mut HashSet::new(),
        );
        assert!(changed);
        assert_eq!(st.allowance.len(), 1);
        assert_eq!(st.allowance[0].day, today);
    }

    // ── license gates ───────────────────────────────────────────────────────

    #[test]
    fn unlicensed_schedule_fire_is_skipped_and_logged_once_per_window() {
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let mut st = State::default();
        st.blocks.push(block(0));
        st.schedules.push(s(540, 60, DAY_MON)); // in window — would fire
        let mut skipped = HashSet::new();

        // The window would fire, but gates.schedules is off: no new active,
        // nothing to persist, and the skip is recorded (that is what gates
        // the log line to once per window).
        let changed = reconcile(
            &mut st,
            now,
            &now_l,
            day_of(&now_l),
            &free_gates(),
            &mut skipped,
        );
        assert!(!changed);
        assert!(st.active.is_empty());
        assert_eq!(skipped.len(), 1);

        // Next tick, same window: already recorded — no second log, still
        // exactly one marker, still no active.
        let changed = reconcile(
            &mut st,
            now + 1,
            &now_l,
            day_of(&now_l),
            &free_gates(),
            &mut skipped,
        );
        assert!(!changed);
        assert!(st.active.is_empty());
        assert_eq!(skipped.len(), 1);
    }

    #[test]
    fn unlicensed_gate_leaves_running_scheduled_active_untouched() {
        // A schedule-fired block is already running (started while licensed);
        // the license then lapses. The active must run to completion: it is
        // retained, not duplicated, and no skip is recorded (the window is
        // still represented in st.active).
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let mut st = State::default();
        st.blocks.push(block(0));
        st.schedules.push(s(540, 60, DAY_MON));
        st.active.push(sched_active(0, 1, now + 1800));
        let mut skipped = HashSet::new();
        let changed = reconcile(
            &mut st,
            now,
            &now_l,
            day_of(&now_l),
            &free_gates(),
            &mut skipped,
        );
        assert!(!changed);
        assert_eq!(st.active.len(), 1);
        assert!(matches!(
            st.active[0].originator,
            Originator::Schedule { schedule_id: 1 }
        ));
        assert!(skipped.is_empty());
    }

    #[test]
    fn schedule_fire_snapshots_app_enforcement_from_gates() {
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);

        // schedules licensed, app blocking not: the fire happens, with
        // apps_enforced snapshotted to false for the block's whole run.
        let mut st = State::default();
        st.blocks.push(block(0));
        st.schedules.push(s(540, 60, DAY_MON));
        let gates = Gates {
            schedules: true,
            app_blocking: false,
        };
        assert!(reconcile(
            &mut st,
            now,
            &now_l,
            day_of(&now_l),
            &gates,
            &mut HashSet::new()
        ));
        assert_eq!(st.active.len(), 1);
        assert!(!st.active[0].apps_enforced);

        // Fully licensed: the snapshot is true.
        let mut st = State::default();
        st.blocks.push(block(0));
        st.schedules.push(s(540, 60, DAY_MON));
        assert!(reconcile(
            &mut st,
            now,
            &now_l,
            day_of(&now_l),
            &all_gates(),
            &mut HashSet::new()
        ));
        assert_eq!(st.active.len(), 1);
        assert!(st.active[0].apps_enforced);
    }

    #[test]
    fn skipped_fire_markers_are_pruned_once_the_window_passes() {
        // 10:30 Monday: the 09:00–10:00 window has ended. A marker recorded
        // during that window must not linger (weekly schedules would
        // otherwise accumulate one marker per occurrence forever).
        let now_l = t(10, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let mut st = State::default();
        st.blocks.push(block(0));
        st.schedules.push(s(540, 60, DAY_MON));
        let window_end = now - 1800; // 10:00, already past
        let mut skipped: HashSet<(u64, u64)> = [(1, window_end)].into_iter().collect();
        reconcile(
            &mut st,
            now,
            &now_l,
            day_of(&now_l),
            &free_gates(),
            &mut skipped,
        );
        assert!(skipped.is_empty());
    }
}
