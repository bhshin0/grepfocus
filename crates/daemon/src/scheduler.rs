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
//!
//! Before those three, the tick folds in what the other tasks counted since
//! the last one — app kills from procwatch, refused connections from the
//! proxy (`apply_attempts`) — and persists those credits on a one-a-minute
//! throttle (`attempt_save_due`): a crash or SIGKILL loses at most a minute
//! of counts, while a quiet block does not fsync every second. The final
//! save on graceful stop (`run_daemon`) catches whatever is left.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Datelike, Local, NaiveDate, TimeZone, Timelike};
use grepfocus_core::license::features;
use grepfocus_core::validate::normalize_domain;
use grepfocus_core::{
    day_set, now_unix, prune_breaks, ActiveBlock, EventKind, FocusSession, Origin, Originator,
    PomodoroPhase, PomodoroSession, Schedule, State, UsageStats, BREAKS_CAP,
    MAX_ALLOWANCE_WINDOW_SECS,
};
use tracing::{debug, error, info, warn};

use crate::{enforce, events, has_feature, state, Daemon};

const TICK: Duration = Duration::from_secs(1);

/// At most one state save a minute for credits alone — attempts and app
/// kills folded in by the tick. This is the bound on what a crash or SIGKILL
/// can lose, and on the fsync rate of a block that is being hammered.
const ATTEMPT_SAVE_SECS: u64 = 60;

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
    // Unix time of the last save this loop made BECAUSE a credit landed — an
    // attempt or an app kill folded in by the tick — as opposed to one for a
    // reconcile or a pomodoro transition. `attempt_save_due` throttles the
    // credit-driven saves to one a minute against it. `0` is "none yet", so
    // the first credit after start persists on its own tick.
    let mut last_attempt_save_unix: u64 = 0;
    loop {
        ticker.tick().await;
        tick(&daemon, &mut skipped_fires, &mut last_attempt_save_unix).await;
    }
}

async fn tick(
    daemon: &Arc<Daemon>,
    skipped_fires: &mut HashSet<(u64, u64)>,
    last_attempt_save_unix: &mut u64,
) {
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
        // Fold any app kills procwatch counted since the last tick into today's
        // rollup. An in-memory bump like the high-water mark above, drained to
        // zero here whether or not we save this tick — but unlike the mark it
        // does not merely ride the next save from any cause: a credit is what
        // the status card shows, so `attempt_save_due` below persists it
        // within a minute (at most one credit-driven fsync a minute).
        let kills = daemon
            .app_kills_pending
            .swap(0, std::sync::atomic::Ordering::Relaxed);
        st.stats.credit_app_kills(today, kills);
        // Same again for the refused connections the proxy observed since the
        // last tick: this is the buffer's single consumer. Two leaf locks,
        // each taken and released in a statement with `state` already held —
        // the `health`/`forwardable` exception to the lock order. The overflow
        // line is a count, never a host: hostnames stay at `debug!` in the
        // proxy.
        let drained = daemon.attempts().drain(now_unix);
        let credited_attempts = !drained.attempts.is_empty()
            && apply_attempts(&mut st, &drained.attempts, today, &mut daemon.events());
        if drained.dropped > 0 {
            debug!(
                dropped = drained.dropped,
                "attempt buffer overflowed between ticks"
            );
        }
        let attempt_save = attempt_save_due(
            kills > 0 || credited_attempts,
            now_unix,
            *last_attempt_save_unix,
        );
        let gates = {
            let lic = daemon.license.lock().await;
            Gates {
                schedules: has_feature(lic.as_ref(), &st, features::SCHEDULES),
                app_blocking: has_feature(lic.as_ref(), &st, features::APP_BLOCKING),
            }
        };
        // Advance the pomodoro phase machine BEFORE reconcile, deliberately:
        // on the last focus interval `advance_pomodoro` only clears the
        // session and leaves the driven `ActiveBlock` in place, handing the
        // drop + single `FocusSession` record to reconcile step 1 in this same
        // tick (the block's `ends_at_unix` == the last focus's `phase_ends`, so
        // step 1 fires). Running first also means the two never fight over
        // `break_until_unix`: advance sets a future break (step 4 leaves it) or
        // clears an elapsed one (step 4 then finds nothing) — either way they
        // converge. A phase transition MUST be persisted or a restart loses it,
        // so its `changed` is OR'd into reconcile's before the save.
        let pomo_changed = {
            // Split the borrow: advance_pomodoro needs `pomodoro` and `active`
            // mutably at once.
            let State {
                pomodoro, active, ..
            } = &mut *st;
            advance_pomodoro(pomodoro, active, now_unix)
        };
        let reconciled = reconcile(&mut st, now_unix, &now_local, today, &gates, skipped_fires);
        if pomo_changed || reconciled || attempt_save {
            match state::save(&st, &daemon.key) {
                // The marker moves only on a save that was due for a credit
                // and succeeded: a failed one is retried by the next credit,
                // and a reconcile-only save leaves the minute's clock alone.
                Ok(()) if attempt_save => *last_attempt_save_unix = now_unix,
                Ok(()) => {}
                Err(e) => error!(?e, "scheduler save failed"),
            }
        }

        let mut pending = daemon.break_challenges.lock().await;
        if !pending.is_empty() {
            prune_break_challenges(&mut pending, &st.active);
        }
    }

    // Reconcile enforcement every tick: sync() is a no-op while the applied
    // union is unchanged, and retries automatically after a failed apply.
    if let Err(e) = enforce::sync(daemon).await {
        error!(?e, "scheduler enforce sync failed");
    }
}

/// Retire break challenges belonging to blocks that are no longer active.
///
/// Without this, a challenge issued during one activation would still verify
/// during the NEXT one: you could request a challenge while calm, keep the
/// string, and spend it in a moment of weakness — defeating the very friction
/// challenge-locked breaks exist to impose. Also bounds the map at one entry
/// per active block.
fn prune_break_challenges(pending: &mut HashMap<u64, String>, active: &[ActiveBlock]) {
    pending.retain(|block_id, _| active.iter().any(|a| a.block.id == *block_id));
}

/// Advance the pomodoro phase machine one tick. Pure over `(session, active,
/// now)` — no clock, no IO — so the transitions are unit-testable. Returns
/// whether anything changed (the caller persists on `true`; an unpersisted
/// phase transition would be lost on restart).
///
/// Runs BEFORE `reconcile` in the tick (see `tick`). Transition rules once the
/// current phase has elapsed (`now >= phase_ends_unix`):
/// * Focus ended, more cycles remain → enter Break: set the driven block's
///   `break_until_unix = now + break_secs` (lifting enforcement directly,
///   never touching the allowance ledger), and move `phase`/`phase_ends`.
/// * Focus ended on the LAST cycle → clear the session and leave the
///   `ActiveBlock` in place; its `ends_at_unix` (the set backstop) equals this
///   focus's `phase_ends`, so reconcile step 1 drops it and records the ONE
///   break-inclusive `FocusSession` through the existing single choke point.
/// * Break ended → bump `cycle_index`, return to Focus, and clear the block's
///   `break_until_unix` (reconcile step 4 would also clear an elapsed break —
///   idempotent; clearing here keeps the block's state self-consistent).
///
/// Prune (checked first): if the session's block is no longer active — expired
/// via its backstop, or force-ended — clear the session, mirroring
/// `prune_break_challenges`.
fn advance_pomodoro(
    session: &mut Option<PomodoroSession>,
    active: &mut [ActiveBlock],
    now: u64,
) -> bool {
    let s = match session {
        Some(s) => s,
        None => return false,
    };

    // Prune: the driven block is gone (backstop expiry recorded it in step 1,
    // or it was force-ended). Nothing left to drive.
    if !active.iter().any(|a| a.block.id == s.block_id) {
        *session = None;
        return true;
    }

    if now < s.phase_ends_unix {
        return false;
    }

    match s.phase {
        PomodoroPhase::Focus => {
            if s.cycle_index + 1 < s.cycles_total {
                // Enter the auto-break: lift enforcement on the driven block.
                if let Some(a) = active.iter_mut().find(|a| a.block.id == s.block_id) {
                    a.break_until_unix = Some(now + s.break_secs);
                }
                s.phase = PomodoroPhase::Break;
                s.phase_ends_unix = now + s.break_secs;
                info!(
                    block_id = s.block_id,
                    cycle_index = s.cycle_index,
                    "pomodoro: focus interval ended, entering break"
                );
                true
            } else {
                // Last focus interval done: the block's backstop has been
                // reached — hand the drop + record to reconcile step 1.
                let block_id = s.block_id;
                *session = None;
                info!(
                    block_id,
                    "pomodoro: final focus interval ended, session complete"
                );
                true
            }
        }
        PomodoroPhase::Break => {
            s.cycle_index += 1;
            s.phase = PomodoroPhase::Focus;
            s.phase_ends_unix = now + s.focus_secs;
            if let Some(a) = active.iter_mut().find(|a| a.block.id == s.block_id) {
                a.break_until_unix = None;
            }
            info!(
                block_id = s.block_id,
                cycle_index = s.cycle_index,
                "pomodoro: break ended, resuming focus"
            );
            true
        }
    }
}

/// Bring `st.active` into agreement with wall-clock expiry and the schedule
/// table, and prune unreachable break history. Pure over its inputs (no
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
/// It also prunes break-history records no allowance policy can still see
/// (retention only — the daily reset lives in the reducers' `day == today`
/// filter), and `skipped_fires` entries whose window has passed.
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

    // Steps 1 and 2 are the SINGLE choke point where a block "ends": a
    // manual block can only end by wall-clock expiry (step 1, no cancel), a
    // scheduled block by expiry or by its window sliding/disabling/deleting
    // (step 2). Both used to be plain `retain` drops; now each dropped active
    // is turned into exactly one recorded `FocusSession`. A daemon restart
    // mid-block emits NO false end — the `ActiveBlock` persists in `State` and
    // is still active on reload, so nothing is dropped here.

    // 1. Expire by wall clock.
    let before = st.active.len();
    let (kept, ended) = partition_active(std::mem::take(&mut st.active), |a| {
        a.ends_at_unix > now_unix
    });
    st.active = kept;
    let expired = before - st.active.len();
    if expired > 0 {
        info!(count = expired, "expired active blocks");
        for a in &ended {
            record_ended_session(&mut st.stats, a, now_unix, today);
        }
        changed = true;
    }

    // 2. End scheduled actives whose driving schedule disappeared,
    //    was disabled, or slid out of its window.
    let before = st.active.len();
    let (kept, ended) = partition_active(std::mem::take(&mut st.active), |a| match &a.originator {
        Originator::Manual => true,
        // Not schedule-window-driven: retained like Manual. A pomodoro active
        // ends only by its own `ends_at_unix` (the set backstop, step 1) or by
        // `stop_pomodoro`; `advance_pomodoro` drives its focus/break rhythm.
        Originator::Pomodoro => true,
        Originator::Schedule { schedule_id } => schedules
            .iter()
            .find(|s| s.id == *schedule_id)
            .map(|s| s.enabled && schedule_active_at(s, now_local))
            .unwrap_or(false),
    });
    st.active = kept;
    let auto_ended = before - st.active.len();
    if auto_ended > 0 {
        info!(count = auto_ended, "ended schedule-driven blocks");
        for a in &ended {
            record_ended_session(&mut st.stats, a, now_unix, today);
        }
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
            // Snapshotted at activation from the saved block, like
            // apps_enforced below: a mid-block edit or license change must
            // never soften a running block's break rules. No license check —
            // the lock was licensed when it was SAVED.
            lock: block.lock,
            // Snapshotted with it, same doctrine: a mid-block edit must never
            // change the budget a running block has already spent against.
            allowance: Some(block.policy()),
            block,
            started_at_unix: now_unix,
            ends_at_unix,
            originator: Originator::Schedule { schedule_id: s.id },
            break_until_unix: None,
            // Snapshotted at activation: a mid-block license change (either
            // direction) never alters a running block's app enforcement.
            apps_enforced: gates.app_blocking,
            attempts: 0,
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

    // Retention on break history: drop records no policy can still see. This
    // is purely a memory bound — the DAILY RESET now lives in the reducers'
    // `day == today` filter, not here. That is strictly more robust than the
    // old "prune everything from previous days" scheme: a daemon that was
    // asleep or stopped across midnight used to depend on this tick running
    // to hand back a fresh per-day budget, and a reducer that filters by day
    // itself simply cannot over-credit whether the tick fired or not.
    // Needs a save, but not a re-apply on its own.
    let pruned = prune_breaks(&mut st.breaks, now_unix, today, MAX_ALLOWANCE_WINDOW_SECS);
    // Window pruning is routine and silent. Cap eviction is not: it drops
    // records a policy could still have counted, so the affected block gets
    // some of its budget handed back. That is a deliberate memory backstop,
    // but it is a LOOSENING of enforcement, so it must never happen quietly —
    // in practice it means something is calling `take_break` in a loop.
    if !pruned.cap_evicted.is_empty() {
        let blocks = pruned
            .cap_evicted
            .iter()
            .map(|(id, n)| format!("{id}={n}"))
            .collect::<Vec<_>>()
            .join(" ");
        warn!(
            evicted = pruned.cap_evicted_total(),
            per_block = %blocks,
            cap = BREAKS_CAP,
            "break history hit the per-block cap; oldest records dropped and \
             their spend no longer counts against the allowance"
        );
    }

    changed || pruned.removed_any()
}

/// Split `active` into `(kept, dropped)` by `keep`. A partition rather than a
/// `retain` so the caller can turn each DROPPED active into a recorded
/// session — `retain` would discard them silently.
fn partition_active(
    active: Vec<ActiveBlock>,
    keep: impl Fn(&ActiveBlock) -> bool,
) -> (Vec<ActiveBlock>, Vec<ActiveBlock>) {
    active.into_iter().partition(keep)
}

/// Record a just-ended block as a completed [`FocusSession`]. The block ended
/// NOW (`now_unix`), so that is its `ended_at_unix` and the duration is
/// `now_unix - started_at_unix`; it is credited to `today` (the local day of
/// that end). Pure — no clock, no IO — so `reconcile` stays unit-testable.
fn record_ended_session(stats: &mut UsageStats, a: &ActiveBlock, now_unix: u64, today: i64) {
    let session = FocusSession {
        block_id: a.block.id,
        name: a.block.name.clone(),
        started_at_unix: a.started_at_unix,
        ended_at_unix: now_unix,
        origin: Origin::from(&a.originator),
        duration_secs: now_unix.saturating_sub(a.started_at_unix),
    };
    stats.credit_session(session, today);
}

/// Credit the attempts the proxy observed since the last tick. For each
/// `(host, unix)`: bump `attempts` on every ACTIVE, NOT-on-break block whose
/// hosts lines covered `host` — its canonical domains contain `host` itself,
/// or the bare `x` of a `www.x` (`hosts::render_block` writes the `www.`
/// alias for every bare entry, so that block's line matched too). If any
/// did, credit the day's stats and push one `Attempt` event, both keyed on
/// the entry text: `host` when a matching block holds it exactly, else the
/// bare name — the fold `enforce::canonical_attempt` makes itself when only
/// the bare entry is enforced — and attributed to the lowest matching block
/// id. Returns whether anything was credited; the caller decides whether
/// that is worth a save (`attempt_save_due`). Pure — no clock, no IO.
///
/// A host no active block claims credits nothing at all. The hook already
/// filtered against the enforced set, so this is defence in depth — and it is
/// what keeps `credit_attempt`'s contract: the key is always a canonical
/// entry of a live block. Each block's domains are normalized once per call,
/// not once per attempt. `today` is the tick's local day, which is the
/// attempt's day too: the buffer is at most a tick old.
fn apply_attempts(
    st: &mut State,
    attempts: &[(String, u64)],
    today: i64,
    log: &mut events::Log,
) -> bool {
    let canonical: Vec<HashSet<String>> = st
        .active
        .iter()
        .map(|a| {
            a.block
                .domains
                .iter()
                .filter_map(|d| normalize_domain(d).ok())
                .collect()
        })
        .collect();
    let mut credited = false;
    for (host, unix) in attempts {
        let bare = www_alias_of(host);
        let mut lowest: Option<u64> = None;
        let mut exact = false;
        for (a, domains) in st.active.iter_mut().zip(&canonical) {
            if a.break_until_unix.is_some_and(|t| t > *unix) {
                continue; // on a break: its domains were not being refused
            }
            let holds_host = domains.contains(host.as_str());
            if !holds_host && !bare.is_some_and(|b| domains.contains(b)) {
                continue;
            }
            exact |= holds_host;
            a.attempts = a.attempts.saturating_add(1);
            lowest = Some(lowest.map_or(a.block.id, |l| l.min(a.block.id)));
        }
        if let Some(block_id) = lowest {
            // `bare` is `Some` whenever `exact` is false: the alias was the
            // only other way in.
            let entry = if exact {
                host.as_str()
            } else {
                bare.unwrap_or(host)
            };
            st.stats.credit_attempt(today, entry);
            log.push(EventKind::Attempt, block_id, entry, *unix);
            credited = true;
        }
    }
    credited
}

/// The bare entry whose `www.` alias `host` is — `x` for `www.x` — or `None`
/// when `host` is not one. Mirrors `hosts::render_block`, which writes
/// `www.x` for an entry `x` unless `x` is itself a `www.` name: `www.www.x`
/// is nobody's alias.
fn www_alias_of(host: &str) -> Option<&str> {
    host.strip_prefix("www.")
        .filter(|bare| !bare.is_empty() && !bare.starts_with("www."))
}

/// Whether the tick should save for the credits it just folded in — see
/// `tick`. Due when something was credited (`credited`) and the last such
/// save (`last_save`, unix seconds; `0` for none yet) lies at least
/// [`ATTEMPT_SAVE_SECS`] from `now` in either direction, so a clock that
/// jumped back cannot stall the saves. Pure, so the boundary is unit-tested.
fn attempt_save_due(credited: bool, now: u64, last_save: u64) -> bool {
    credited && now.abs_diff(last_save) >= ATTEMPT_SAVE_SECS
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
    use grepfocus_core::{AllowancePolicy, Block, BreakRecord, LockMode, DAY_MON};

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
            allowance: None,
            lock: LockMode::Unlocked,
        }
    }

    #[test]
    fn stale_break_challenges_are_retired_when_a_block_deactivates() {
        // The replay this closes: request a challenge while calm, keep the
        // string, spend it on the NEXT activation. Once the block is no
        // longer active its challenge must be gone.
        let mut pending = HashMap::from([
            (1, "still-active-keeps-its-challenge".to_string()),
            (2, "ended-block-must-lose-its-challenge".to_string()),
        ]);
        prune_break_challenges(&mut pending, &[manual_active(1, 9_999)]);
        assert_eq!(pending.len(), 1);
        assert!(pending.contains_key(&1));
        assert!(!pending.contains_key(&2));

        // Nothing active at all: the map empties.
        prune_break_challenges(&mut pending, &[]);
        assert!(pending.is_empty());
    }

    fn manual_active(block_id: u64, ends_at_unix: u64) -> ActiveBlock {
        ActiveBlock {
            block: block(block_id),
            started_at_unix: 0,
            ends_at_unix,
            originator: Originator::Manual,
            break_until_unix: None,
            allowance: None,
            apps_enforced: false,
            lock: LockMode::Unlocked,
            attempts: 0,
        }
    }

    fn sched_active(block_id: u64, schedule_id: u64, ends_at_unix: u64) -> ActiveBlock {
        ActiveBlock {
            block: block(block_id),
            started_at_unix: 0,
            ends_at_unix,
            originator: Originator::Schedule { schedule_id },
            break_until_unix: None,
            allowance: None,
            apps_enforced: false,
            lock: LockMode::Unlocked,
            attempts: 0,
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

    // Activation site 3 of 3: a schedule fire snapshots the saved block's
    // allowance policy onto the new active record, like `lock` and
    // `apps_enforced` beside it.
    #[test]
    fn schedule_fire_snapshots_the_allowance_policy() {
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let mut st = State::default();
        let mut b = block(0);
        b.set_policy(AllowancePolicy::RollingWindow {
            secs: 300,
            window_secs: 3600,
        });
        st.blocks.push(b);
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
        assert_eq!(
            st.active[0].allowance,
            Some(AllowancePolicy::RollingWindow {
                secs: 300,
                window_secs: 3600,
            })
        );
    }

    #[test]
    fn prunes_break_history_on_the_tick() {
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let today = day_of(&now_l);
        let mut st = State::default();
        // Older than the longest permitted window AND from another day: the
        // only combination no policy can still see.
        st.breaks.push(BreakRecord {
            block_id: 0,
            start_unix: now - MAX_ALLOWANCE_WINDOW_SECS - 60,
            secs: 100,
            day: today - 1,
        });
        // Yesterday but still inside the window (a break just before local
        // midnight) — a rolling policy still counts it, so it must survive.
        st.breaks.push(BreakRecord {
            block_id: 0,
            start_unix: now - 60,
            secs: 50,
            day: today - 1,
        });
        // Today's own row, kept by the day condition regardless of age.
        st.breaks.push(BreakRecord {
            block_id: 0,
            start_unix: now - MAX_ALLOWANCE_WINDOW_SECS - 30,
            secs: 25,
            day: today,
        });
        let changed = reconcile(
            &mut st,
            now,
            &now_l,
            today,
            &all_gates(),
            &mut HashSet::new(),
        );
        // Pruning alone contributes to `changed`, exactly as the ledger
        // retain used to, so the tick still persists the shrunken history.
        assert!(changed);
        assert_eq!(st.breaks.len(), 2);
        assert!(st.breaks.iter().any(|r| r.secs == 50));
        assert!(st.breaks.iter().any(|r| r.secs == 25));
    }

    #[test]
    fn reconcile_reports_unchanged_when_nothing_is_pruned() {
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let today = day_of(&now_l);
        let mut st = State::default();
        st.breaks.push(BreakRecord {
            block_id: 0,
            start_unix: now - 60,
            secs: 50,
            day: today,
        });
        let changed = reconcile(
            &mut st,
            now,
            &now_l,
            today,
            &all_gates(),
            &mut HashSet::new(),
        );
        assert!(!changed);
        assert_eq!(st.breaks.len(), 1);
    }

    // ── session recording (B2.b) ────────────────────────────────────────────

    #[test]
    fn wall_clock_expiry_records_exactly_one_session() {
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let today = day_of(&now_l);
        let mut st = State::default();
        let mut ended = manual_active(0, now - 1); // ended a second ago
        ended.started_at_unix = now - 100; // ran 100s
        st.active.push(ended);
        st.active.push(manual_active(1, now + 100)); // still live → no session
        let changed = reconcile(
            &mut st,
            now,
            &now_l,
            today,
            &all_gates(),
            &mut HashSet::new(),
        );
        assert!(changed);
        // Exactly one session recorded, for the ended block, credited to today.
        assert_eq!(st.stats.sessions.len(), 1);
        let s = &st.stats.sessions[0];
        assert_eq!(s.block_id, 0);
        assert_eq!(s.origin, Origin::Manual);
        assert_eq!(s.ended_at_unix, now);
        assert_eq!(s.duration_secs, 100);
        assert_eq!(st.stats.days.len(), 1);
        assert_eq!(st.stats.days[0].day, today);
        assert_eq!(st.stats.days[0].focus_secs, 100);
        assert_eq!(st.stats.days[0].sessions_completed, 1);
        assert_eq!(st.stats.totals.sessions, 1);
    }

    #[test]
    fn schedule_end_records_a_schedule_origin_session() {
        // Disabled schedule → its active is dropped in step 2 and recorded.
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let today = day_of(&now_l);
        let mut st = State::default();
        st.blocks.push(block(0));
        let mut sch = s(540, 60, DAY_MON);
        sch.enabled = false;
        st.schedules.push(sch);
        let mut a = sched_active(0, 1, now + 3600);
        a.started_at_unix = now - 42;
        st.active.push(a);
        let changed = reconcile(
            &mut st,
            now,
            &now_l,
            today,
            &all_gates(),
            &mut HashSet::new(),
        );
        assert!(changed);
        assert_eq!(st.stats.sessions.len(), 1);
        assert_eq!(st.stats.sessions[0].origin, Origin::Schedule);
        assert_eq!(st.stats.sessions[0].duration_secs, 42);
    }

    #[test]
    fn persisted_midblock_active_records_no_session() {
        // The reload case: an active that is still live (ends in the future)
        // is retained untouched and emits NO session — a daemon restart
        // mid-block must never record a false end.
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let mut st = State::default();
        st.active.push(manual_active(0, now + 3600));
        let changed = reconcile(
            &mut st,
            now,
            &now_l,
            day_of(&now_l),
            &all_gates(),
            &mut HashSet::new(),
        );
        assert!(!changed);
        assert_eq!(st.active.len(), 1);
        assert!(st.stats.sessions.is_empty());
        assert!(st.stats.days.is_empty());
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
    fn schedule_fire_snapshots_lock_from_the_saved_block() {
        // A schedule-fired active carries the saved block's lock mode in its
        // activation snapshot — the field TakeBreak enforcement reads.
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let mut st = State::default();
        let mut b = block(0);
        b.lock = LockMode::ChallengeBreaks;
        st.blocks.push(b);
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
        assert_eq!(st.active[0].lock, LockMode::ChallengeBreaks);

        // And an Unlocked block snapshots Unlocked.
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
        assert_eq!(st.active[0].lock, LockMode::Unlocked);
    }

    // ── pomodoro: advance_pomodoro (B2.c) ───────────────────────────────────

    fn pomo_active(block_id: u64, ends_at_unix: u64) -> ActiveBlock {
        ActiveBlock {
            block: block(block_id),
            started_at_unix: 0,
            ends_at_unix,
            originator: Originator::Pomodoro,
            break_until_unix: None,
            allowance: None,
            apps_enforced: false,
            lock: LockMode::Unlocked,
            attempts: 0,
        }
    }

    fn pomo_session(
        block_id: u64,
        phase: PomodoroPhase,
        cycle_index: u32,
        cycles_total: u32,
        phase_ends_unix: u64,
    ) -> PomodoroSession {
        PomodoroSession {
            block_id,
            focus_secs: 1500,
            break_secs: 300,
            cycles_total,
            cycle_index,
            phase,
            phase_ends_unix,
        }
    }

    #[test]
    fn advance_pomodoro_none_and_before_phase_end_are_noops() {
        assert!(!advance_pomodoro(&mut None, &mut [], 1000));

        let mut session = Some(pomo_session(1, PomodoroPhase::Focus, 0, 4, 2000));
        let mut active = vec![pomo_active(1, u64::MAX)];
        // now < phase_ends: nothing changes — this is also the restart-resume
        // shape (an in-flight focus interval keeps running on reload).
        assert!(!advance_pomodoro(&mut session, &mut active, 1000));
        let s = session.unwrap();
        assert_eq!(s.phase, PomodoroPhase::Focus);
        assert_eq!(s.cycle_index, 0);
        assert!(active[0].break_until_unix.is_none());
    }

    #[test]
    fn advance_pomodoro_focus_to_break_sets_break_until() {
        let now = 2000;
        let mut session = Some(pomo_session(1, PomodoroPhase::Focus, 0, 4, now));
        let mut active = vec![pomo_active(1, u64::MAX)];
        assert!(advance_pomodoro(&mut session, &mut active, now));
        let s = session.unwrap();
        assert_eq!(s.phase, PomodoroPhase::Break);
        assert_eq!(s.cycle_index, 0); // not yet bumped — that happens on resume
        assert_eq!(s.phase_ends_unix, now + s.break_secs);
        assert_eq!(active[0].break_until_unix, Some(now + 300));
    }

    #[test]
    fn advance_pomodoro_break_to_focus_bumps_cycle_and_clears_break() {
        let now = 2000;
        let mut session = Some(pomo_session(1, PomodoroPhase::Break, 0, 4, now));
        let mut active = vec![pomo_active(1, u64::MAX)];
        active[0].break_until_unix = Some(now - 5); // break has elapsed
        assert!(advance_pomodoro(&mut session, &mut active, now));
        let s = session.unwrap();
        assert_eq!(s.phase, PomodoroPhase::Focus);
        assert_eq!(s.cycle_index, 1);
        assert_eq!(s.phase_ends_unix, now + s.focus_secs);
        assert!(active[0].break_until_unix.is_none());
    }

    #[test]
    fn advance_pomodoro_last_focus_clears_session_but_keeps_block() {
        let now = 2000;
        // cycle_index + 1 == cycles_total: the final focus interval.
        let mut session = Some(pomo_session(1, PomodoroPhase::Focus, 3, 4, now));
        let mut active = vec![pomo_active(1, now)]; // backstop reached
        assert!(advance_pomodoro(&mut session, &mut active, now));
        assert!(session.is_none(), "session cleared on the last focus");
        // The block is LEFT for reconcile step 1 to drop + record.
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn advance_pomodoro_prunes_when_block_gone() {
        // The driven block expired via its backstop (or was force-ended) and
        // is no longer active: clear the orphaned session.
        let mut session = Some(pomo_session(1, PomodoroPhase::Break, 1, 4, 5000));
        let mut active: Vec<ActiveBlock> = vec![];
        assert!(advance_pomodoro(&mut session, &mut active, 1000));
        assert!(session.is_none());
    }

    #[test]
    fn pomodoro_last_cycle_records_exactly_one_pomodoro_session() {
        // The tick order: advance_pomodoro (clears the session on the final
        // focus) THEN reconcile step 1 (drops the backstop-reached block and
        // records the ONE break-inclusive FocusSession, origin Pomodoro).
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let today = day_of(&now_l);
        let mut st = State::default();
        let mut a = pomo_active(0, now); // ends_at == now (set backstop reached)
        a.started_at_unix = now - 100; // ran 100s wall-clock
        st.active.push(a);
        st.pomodoro = Some(pomo_session(0, PomodoroPhase::Focus, 3, 4, now));

        let pomo_changed = advance_pomodoro(&mut st.pomodoro, &mut st.active, now);
        assert!(pomo_changed);
        assert!(st.pomodoro.is_none());
        let reconciled = reconcile(
            &mut st,
            now,
            &now_l,
            today,
            &all_gates(),
            &mut HashSet::new(),
        );
        assert!(reconciled);
        assert!(st.active.is_empty());
        assert_eq!(st.stats.sessions.len(), 1);
        assert_eq!(st.stats.sessions[0].origin, Origin::Pomodoro);
        assert_eq!(st.stats.sessions[0].duration_secs, 100);
        assert_eq!(st.stats.totals.sessions, 1);
    }

    #[test]
    fn reconcile_retains_a_running_pomodoro_active() {
        // Step 2 retains a Pomodoro active like Manual — it is not
        // schedule-window-driven. A mid-focus session on reload keeps running
        // and records no false end.
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let mut st = State::default();
        st.active.push(pomo_active(0, now + 3600)); // backstop in the future
        st.pomodoro = Some(pomo_session(0, PomodoroPhase::Focus, 0, 4, now + 1500));
        let pomo_changed = advance_pomodoro(&mut st.pomodoro, &mut st.active, now);
        let reconciled = reconcile(
            &mut st,
            now,
            &now_l,
            day_of(&now_l),
            &all_gates(),
            &mut HashSet::new(),
        );
        assert!(!pomo_changed);
        assert!(!reconciled);
        assert_eq!(st.active.len(), 1);
        assert!(st.pomodoro.is_some());
        assert!(st.stats.sessions.is_empty());
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

    // ── apply_attempts() ────────────────────────────────────────────────────

    /// An active block `id` over `domains`, on a break until `break_until`
    /// if set.
    fn active_over(id: u64, domains: &[&str], break_until: Option<u64>) -> ActiveBlock {
        let mut a = manual_active(id, u64::MAX);
        a.block.domains = domains.iter().map(|d| d.to_string()).collect();
        a.break_until_unix = break_until;
        a
    }

    fn attempt(host: &str, unix: u64) -> (String, u64) {
        (host.to_string(), unix)
    }

    #[test]
    fn attempt_credits_day_totals_active_counter_and_event() {
        let mut st = State::default();
        st.active.push(active_over(5, &["reddit.com"], None));
        let mut log = events::Log::default();
        assert!(apply_attempts(
            &mut st,
            &[attempt("reddit.com", 1_000), attempt("reddit.com", 1_010)],
            42,
            &mut log,
        ));
        // The live per-run counter on the block.
        assert_eq!(st.active[0].attempts, 2);
        // The day row, its total and the lifetime total.
        assert_eq!(st.stats.days.len(), 1);
        assert_eq!(st.stats.days[0].day, 42);
        assert_eq!(st.stats.days[0].attempts["reddit.com"], 2);
        assert_eq!(st.stats.days[0].attempts_total, 2);
        assert_eq!(st.stats.totals.attempts, 2);
        // One event per attempt, stamped with the attempt's own time.
        let events = log.snapshot();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, EventKind::Attempt);
        assert_eq!(events[0].block_id, 5);
        assert_eq!(events[0].detail, "reddit.com");
        assert_eq!(events[0].unix, 1_000);
        assert_eq!(events[1].unix, 1_010);
    }

    #[test]
    fn on_break_block_is_not_credited() {
        let mut st = State::default();
        // On a break at the attempt's time: the domain was resolving again,
        // so nothing refused belongs to this block.
        st.active.push(active_over(5, &["reddit.com"], Some(2_000)));
        let mut log = events::Log::default();
        assert!(!apply_attempts(
            &mut st,
            &[attempt("reddit.com", 1_000)],
            42,
            &mut log
        ));
        assert_eq!(st.active[0].attempts, 0);
        assert!(st.stats.days.is_empty());
        assert_eq!(st.stats.totals.attempts, 0);
        assert!(log.snapshot().is_empty());

        // The break has elapsed by the attempt's time: credited again.
        assert!(apply_attempts(
            &mut st,
            &[attempt("reddit.com", 2_000)],
            42,
            &mut log
        ));
        assert_eq!(st.active[0].attempts, 1);
        assert_eq!(log.snapshot().len(), 1);
    }

    #[test]
    fn host_in_two_blocks_bumps_both_but_emits_one_event() {
        let mut st = State::default();
        // A stored copy need not be canonical: the match is on the
        // normalized domain, as the hosts file was written.
        st.active.push(active_over(9, &["Reddit.com."], None));
        st.active
            .push(active_over(3, &["reddit.com", "x.com"], None));
        st.active.push(active_over(4, &["x.com"], None));
        let mut log = events::Log::default();
        apply_attempts(&mut st, &[attempt("reddit.com", 1_000)], 42, &mut log);
        assert_eq!(st.active[0].attempts, 1);
        assert_eq!(st.active[1].attempts, 1);
        assert_eq!(st.active[2].attempts, 0, "x.com was not attempted");
        // One attempt is one attempt: the stats count it once, and the one
        // event goes to the lowest matching block id, whatever the order.
        assert_eq!(st.stats.days[0].attempts["reddit.com"], 1);
        assert_eq!(st.stats.totals.attempts, 1);
        let events = log.snapshot();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].block_id, 3);
    }

    #[test]
    fn unknown_host_is_ignored() {
        let mut st = State::default();
        st.active.push(active_over(5, &["reddit.com"], None));
        let mut log = events::Log::default();
        // Not an entry of any active block — a subdomain, a stranger —
        // credits nothing: no counter, no stats row, no event, and the call
        // reports it. Nothing active at all, same. (The `www.` alias of an
        // entry is not a stranger: see the test below.)
        for host in ["old.reddit.com", "myapp.test"] {
            assert!(!apply_attempts(
                &mut st,
                &[attempt(host, 1_000)],
                42,
                &mut log
            ));
        }
        assert_eq!(st.active[0].attempts, 0);
        assert!(st.stats.days.is_empty());
        assert_eq!(st.stats.totals.attempts, 0);
        assert!(log.snapshot().is_empty());
        st.active.clear();
        assert!(!apply_attempts(
            &mut st,
            &[attempt("reddit.com", 1_000)],
            42,
            &mut log
        ));
        assert!(st.stats.days.is_empty());
        assert!(log.snapshot().is_empty());
    }

    #[test]
    fn www_alias_credits_every_block_whose_hosts_line_matched() {
        // Two blocks cover `www.reddit.com`: one holds that entry, the other
        // holds `reddit.com`, for which the hosts file writes the `www.` line
        // too. The hook reports the exact enforced entry; both blocks' lines
        // matched, so both are credited, and the stats row and the one event
        // use the exact entry.
        let mut st = State::default();
        st.active.push(active_over(9, &["reddit.com"], None));
        st.active.push(active_over(3, &["www.reddit.com"], None));
        let mut log = events::Log::default();
        assert!(apply_attempts(
            &mut st,
            &[attempt("www.reddit.com", 1_000)],
            42,
            &mut log
        ));
        assert_eq!(st.active[0].attempts, 1);
        assert_eq!(st.active[1].attempts, 1);
        assert_eq!(st.stats.days[0].attempts["www.reddit.com"], 1);
        assert_eq!(st.stats.days[0].attempts.get("reddit.com"), None);
        assert_eq!(st.stats.totals.attempts, 1);
        let events = log.snapshot();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].block_id, 3);
        assert_eq!(events[0].detail, "www.reddit.com");

        // Only the bare entry is active: the alias folds to it, exactly as
        // the hook would have folded had `www.reddit.com` not been enforced.
        st.active.remove(1);
        assert!(apply_attempts(
            &mut st,
            &[attempt("www.reddit.com", 1_010)],
            42,
            &mut log
        ));
        assert_eq!(st.active[0].attempts, 2);
        assert_eq!(st.stats.days[0].attempts["reddit.com"], 1);
        assert_eq!(st.stats.totals.attempts, 2);
        assert_eq!(log.snapshot()[1].detail, "reddit.com");

        // A `www.` entry gets no `www.www.` line, so it is nobody's alias.
        st.active.clear();
        st.active.push(active_over(4, &["www.only.example"], None));
        assert!(!apply_attempts(
            &mut st,
            &[attempt("www.www.only.example", 1_020)],
            42,
            &mut log
        ));
        assert_eq!(st.active[0].attempts, 0);
        assert_eq!(log.snapshot().len(), 2);
    }

    #[test]
    fn www_alias_of_mirrors_the_hosts_file() {
        assert_eq!(www_alias_of("www.reddit.com"), Some("reddit.com"));
        assert_eq!(www_alias_of("reddit.com"), None);
        assert_eq!(www_alias_of("www.www.x"), None);
        assert_eq!(www_alias_of("www."), None);
        assert_eq!(www_alias_of(""), None);
    }

    // ── attempt_save_due() ──────────────────────────────────────────────────

    #[test]
    fn attempt_save_is_due_a_minute_after_the_last_one() {
        let last = 10_000;
        // Nothing credited: never due, however long it has been.
        assert!(!attempt_save_due(false, last + 3_600, last));
        assert!(!attempt_save_due(false, last + 3_600, 0));
        // Credited: due at exactly a minute, not a second before.
        assert!(!attempt_save_due(true, last, last));
        assert!(!attempt_save_due(true, last + ATTEMPT_SAVE_SECS - 1, last));
        assert!(attempt_save_due(true, last + ATTEMPT_SAVE_SECS, last));
        assert!(attempt_save_due(true, last + ATTEMPT_SAVE_SECS + 1, last));
        // No save yet (`0`): the first credit saves at once.
        assert!(attempt_save_due(true, last, 0));
        // A clock that jumped back past the window does not stall the saves.
        assert!(!attempt_save_due(true, last - ATTEMPT_SAVE_SECS + 1, last));
        assert!(attempt_save_due(true, last - ATTEMPT_SAVE_SECS, last));
    }
}
