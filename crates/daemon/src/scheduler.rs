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

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Datelike, Local, NaiveDate, TimeZone, Timelike};
use frostbite_core::{day_set, now_unix, ActiveBlock, Originator, Schedule};
use tracing::{error, info, warn};

use crate::{enforce, state, Daemon};

const TICK: Duration = Duration::from_secs(1);

pub async fn run(daemon: Arc<Daemon>) {
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        tick(&daemon).await;
    }
}

async fn tick(daemon: &Arc<Daemon>) {
    let now_unix = now_unix();
    let now_local = Local::now();

    let domains_to_apply = {
        let mut st = daemon.state.lock().await;

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
                .map(|s| s.enabled && schedule_active_at(s, &now_local))
                .unwrap_or(false),
        });
        let auto_ended = before - st.active.len();
        if auto_ended > 0 {
            info!(count = auto_ended, "ended schedule-driven blocks");
            changed = true;
        }

        // 3. Auto-start schedules whose window is now open.
        for s in &schedules {
            if !s.enabled || !schedule_active_at(s, &now_local) {
                continue;
            }
            let already_active = st.active.iter().any(|a| {
                matches!(&a.originator, Originator::Schedule { schedule_id } if *schedule_id == s.id)
            });
            if already_active {
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
            let ends_at_unix = compute_window_end_unix(s, &now_local);
            st.active.push(ActiveBlock {
                block,
                started_at_unix: now_unix,
                ends_at_unix,
                originator: Originator::Schedule { schedule_id: s.id },
                break_until_unix: None,
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
        let today = local_day();
        let before = st.allowance.len();
        st.allowance.retain(|l| l.day == today);
        let ledger_pruned = st.allowance.len() != before;

        if changed || ledger_pruned {
            if let Err(e) = state::save(&st, &daemon.key) {
                error!(?e, "scheduler save failed");
            }
        }
        if changed {
            Some(enforce::union_domains(&st.active, now_unix))
        } else {
            None
        }
    };

    if let Some(domains) = domains_to_apply {
        if let Err(e) = enforce::apply(&domains) {
            error!(?e, "scheduler enforce::apply failed");
        }
    }
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
    use frostbite_core::DAY_MON;

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
}
