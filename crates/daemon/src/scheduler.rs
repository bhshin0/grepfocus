//! Reconciles `state.active` against (a) expiry on the daemon's trusted
//! block clock (`clock`) and (b) recurring `state.schedules`. Runs once per
//! second.
//!
//! Three jobs per tick, performed under a single state lock:
//! 1. Drop any active blocks whose `ends_at_unix <= now`. This is the ONLY
//!    way a block ends: a schedule-started block runs to the window end it
//!    snapshotted when it fired, whatever happens to its schedule meanwhile.
//! 2. Start any enabled schedule that is currently in its window and not
//!    already represented in `state.active`.
//! 3. Clear breaks that have elapsed (enforcement resumes).
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

use chrono::{
    DateTime, Datelike, Local, LocalResult, NaiveDate, NaiveDateTime, TimeZone, Timelike,
};
use grepfocus_core::license::features;
use grepfocus_core::validate::normalize_domain;
use grepfocus_core::{
    day_set, prune_breaks, ActiveBlock, EventKind, FocusSession, Origin, Originator, PomodoroPhase,
    PomodoroSession, Schedule, State, UsageStats, BREAKS_CAP, MAX_ALLOWANCE_WINDOW_SECS,
};
use tracing::{debug, error, info, warn};

use crate::{clock, enforce, events, has_feature, state, Daemon};

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
    // Both clocks in one breath, before the lock: the block clock advances
    // on them below. Schedules fire by LOCAL WALL time by design — stepping
    // the clock to make a window open is not a bypass, since the block it
    // starts then runs the window's remaining length on the block clock —
    // so `now_local` stays the wall clock, as does the high-water mark.
    let readings = clock::read();
    let wall_unix = readings.wall_unix;
    let now_local = Local::now();
    let today = now_local.date_naive().num_days_from_ce() as i64;

    {
        let mut st = daemon.state.lock().await;
        // Track the highest WALL time ever observed (clock-rollback guard
        // for license expiry — see `crate::effective_now`). Deliberately
        // bumped in-memory only: an fsync every second is unacceptable disk
        // churn, so the mark persists opportunistically whenever anything
        // else saves. Accepted trade-off: after a crash the stored mark lags
        // by however long the state went unsaved, so a rollback attacker
        // gains at most that window.
        if wall_unix > st.high_water_unix {
            st.high_water_unix = wall_unix;
        }
        // Advance the trusted block clock and take this tick's `now` from
        // it: every expiry, break and phase decision below is in that frame
        // (see `clock`). A step is reported once, on the tick that sees it.
        // The leaf lock is taken and released in this block with `state`
        // held — the `health`/`forwardable` exception to the lock order.
        let now_unix = {
            let idle = st.active.is_empty() && st.pomodoro.is_none();
            let mut block_clock = daemon.clock();
            match block_clock.advance(readings, idle) {
                clock::Step::Tracked => {}
                clock::Step::Jumped { secs } if idle => info!(
                    step_secs = secs,
                    "clock step detected while idle; block clock resynced to the wall clock"
                ),
                clock::Step::Jumped { secs } => warn!(
                    step_secs = secs,
                    "clock step of {secs:+} s detected; block timing continues on elapsed time"
                ),
            }
            block_clock.now_at(readings)
        };
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
        // `break_until_unix`: advance sets a future break (step 3 leaves it) or
        // clears an elapsed one (step 3 then finds nothing) — either way they
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
        // Where the block clock stands, so a restart within this boot resumes
        // it (`clock::BlockClock::resume`). Updated in memory every tick and
        // persisted by whichever save comes next, like `high_water_unix`.
        st.clock_anchor = Some(daemon.clock().anchor(&daemon.boot_id));
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
///   `break_until_unix` (reconcile step 3 would also clear an elapsed break —
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

/// Bring `st.active` into agreement with expiry and the schedule table, and
/// prune unreachable break history. `now_unix` is the trusted block clock's
/// reading for this tick (`clock`), `now_local` the local wall time the
/// schedule windows are defined in. Pure over its inputs (no clock, no IO)
/// so it can be unit-tested. Returns whether anything changed and the state
/// therefore needs persisting.
///
/// Steps, in order:
/// 1. Drop actives whose `ends_at_unix <= now_unix`. The schedule table is
///    NOT consulted here: a schedule-started active carries the end of the
///    window it fired for in `ends_at_unix`, and nothing done to the schedule
///    afterwards — disable, edit, delete — touches that record. The edit
///    applies from the schedule's next window; an edit that EXTENDS the
///    running window makes it re-fire at the old end (step 2 finds the block
///    no longer active and the window still open), which is two sessions.
/// 2. Start any enabled schedule currently in-window and not already active —
///    unless `gates.schedules` is off, in which case the fire is skipped (and
///    logged once per window via `skipped_fires`). New actives snapshot
///    `gates.app_blocking` into `apps_enforced` and, into `ends_at_unix`,
///    the window's remaining length added to `now_unix`: the end is in the
///    block clock's frame like every other end step 1 judges, NOT the wall
///    instant the window closes at. The frames diverge whenever the block
///    clock is ahead of a wall clock that was set back (during a running
///    block, or across a reboot with a persisted active); a wall-instant end
///    already behind `now_unix` would be born expired, dropped by step 1 on
///    the next tick as a one-second session, and fired again — a save, a
///    hosts rewrite and two log lines every second for the whole window.
/// 3. Clear breaks that have elapsed (enforcement resumes).
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

    // Step 1 is the SINGLE choke point where a block "ends": by expiry of
    // its `ends_at_unix`, and by nothing else — a manual block has no cancel,
    // a scheduled block snapshotted its window end when it fired and keeps
    // it through any later change to the schedule, and a pomodoro active
    // ends only by the set's backstop or `stop_pomodoro` (which sets the end
    // to now so this step records it). The drop is a partition, not a
    // `retain`, so each dropped active is turned into exactly one recorded
    // `FocusSession`. A daemon restart mid-block emits NO false end — the
    // `ActiveBlock` persists in `State` and is still active on reload, so
    // nothing is dropped here.

    // 1. Expire on the block clock.
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

    // 2. Auto-start schedules whose window is now open.
    //
    // The wall clock, in the frame the windows and the skip markers' ends
    // are defined in. Drop skip-log markers for windows that have passed
    // first, so the set can't grow across weeks of unlicensed uptime —
    // judged in that frame: pruned against `now_unix` instead, a block clock
    // ahead of the wall clock would drop a live window's marker every tick
    // and re-log the skip every second.
    let wall_now = now_local.timestamp().max(0) as u64;
    skipped_fires.retain(|&(_, window_end)| window_end > wall_now);
    for s in &schedules {
        if !s.enabled {
            continue;
        }
        // The window's end on the wall clock, None while the schedule is in
        // none of its windows. One evaluation keys the skip marker and sizes
        // the new active below.
        let Some(window_end) = window_end_unix_at(s, now_local) else {
            continue;
        };
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
            if skipped_fires.insert((s.id, window_end)) {
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
        // The window's remaining length by the wall clock, applied to the
        // block clock: see the doc comment's step 2 for why not the wall
        // instant itself. Zero cannot happen while the window is open (the
        // minute-of-day check leaves at least a second), but a zero-length
        // active would be born expired, so never push one.
        let remaining = window_end.saturating_sub(wall_now);
        if remaining == 0 {
            continue;
        }
        let ends_at_unix = now_unix + remaining;
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

    // 3. Resume any block whose break has ended (enforcement returns).
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

/// The start DATE of the window instance of `s` that contains `t`, if any.
///
/// A window belongs to the weekday it STARTS on. Its same-day part,
/// `[start, min(end, 1440))`, is live on a selected weekday; a window with
/// `end > 1440` spills into `[0, end - 1440)` of the NEXT day, live there
/// when the PREVIOUS weekday is selected — "Mon 23:00 for 2 h" is in
/// progress at 00:30 on Tuesday iff Monday is selected. Validation caps the
/// length at 1440, so `end - 1440 <= start` and one schedule's two parts
/// never overlap (half-open): at most one instance is live per schedule.
/// Generic over the zone so the DST cases are testable without the test
/// box's local zone.
fn window_start_date_at<Tz: TimeZone>(s: &Schedule, t: &DateTime<Tz>) -> Option<NaiveDate> {
    let weekday = t.weekday().num_days_from_sunday() as u8; // 0=Sun..6=Sat
    let minute = t.hour() * 60 + t.minute();
    let start = s.start_minute as u32;
    let end = start + s.duration_minutes as u32;
    let today = t.date_naive();
    if day_set(s.days, weekday) && start <= minute && minute < end.min(1440) {
        return Some(today);
    }
    if end > 1440 && day_set(s.days, (weekday + 6) % 7) && minute < end - 1440 {
        return Some(today - chrono::Duration::days(1));
    }
    None
}

/// True if `t` falls inside one of the schedule's windows.
#[cfg(test)]
fn schedule_active_at<Tz: TimeZone>(s: &Schedule, t: &DateTime<Tz>) -> bool {
    window_end_unix_at(s, t).is_some()
}

/// The unix-time end of the window instance of `s` containing `t`, or None
/// when `t` is in none of its windows. Keyed off the instance's start DATE,
/// so a spanning window reports the same instant before and after midnight
/// — the `skipped_fires` marker and a fired block's remaining length agree
/// across the boundary.
///
/// The end is the LATER of two readings, so a block never runs shorter than
/// configured on either DST night: the window's wall-clock end, and its
/// wall-clock start plus its length, each resolved by
/// `local_instant_at_or_after`. On a fall-back night the wall end wins: a
/// window ending in the repeated hour ends at the later of its two
/// instants, an hour longer. On a spring-forward night start-plus-length
/// wins whenever the skipped hour is inside the window — whether the window
/// ENDS in it (the wall end resolves an hour on, and the two readings
/// agree) or straddles it (the wall end exists, but comes an hour early in
/// real time) — and the window keeps its real length. One side effect:
/// "00:00 for 24 h" opened on the spring-forward day ends at 01:00 the next
/// day, an hour into its next instance, which fires when it ends
/// (`reconcile` keeps one active per block). A window that STARTS in the
/// skipped hour fires when the clock reaches it, at the end of the gap; its
/// start resolves an hour on like an end would, so from that late fire it
/// runs its full length and up to an hour more.
fn window_end_unix_at<Tz: TimeZone>(s: &Schedule, t: &DateTime<Tz>) -> Option<u64> {
    let start_date = window_start_date_at(s, t)?;
    let tz = t.timezone();
    let start = s.start_minute as u32;
    let end = start + s.duration_minutes as u32;
    let start_naive = start_date
        .and_hms_opt(start / 60, start % 60, 0)
        .expect("validated h/m");
    // `end / 1440` is 0 while the window ends within its start day and 1
    // once it ends at or past the following midnight — an end of exactly
    // 1440 is 00:00 of the next day, not 24:00 of this one.
    let end_date = start_date + chrono::Duration::days((end / 1440) as i64);
    let end_naive = end_date
        .and_hms_opt((end % 1440) / 60, end % 60, 0)
        .expect("validated h/m");
    let by_wall = local_instant_at_or_after(&tz, end_naive).timestamp();
    let by_length = local_instant_at_or_after(&tz, start_naive).timestamp()
        + i64::from(s.duration_minutes) * 60;
    Some(by_wall.max(by_length).max(0) as u64)
}

/// The instant at which `tz` reads `naive` on its wall clock, resolved for
/// the two nights a year it is not one-to-one. On a fall-back night the
/// wall time happens twice: the LATER instant, so a window ending in the
/// repeated hour runs longer rather than shorter. On a spring-forward night
/// the wall time never happens: step an hour at a time until one does, so
/// a window ending in the skipped hour keeps its configured real length
/// instead of losing the hour. DST gaps are one hour; a zone's one-off
/// offset change can be wider, up to the whole day a move across the date
/// line skips, so the steps go on for 25 hours. No real zone skips more
/// than that, which makes the fallback after them — the wall time read as
/// UTC, off by the zone's offset — unreachable in practice; it is there so
/// the tick can neither loop unbounded nor panic should zone data say
/// otherwise.
fn local_instant_at_or_after<Tz: TimeZone>(tz: &Tz, naive: NaiveDateTime) -> DateTime<Tz> {
    for hours in 0..=25 {
        match tz.from_local_datetime(&(naive + chrono::Duration::hours(hours))) {
            LocalResult::Single(t) => return t,
            LocalResult::Ambiguous(_, later) => return later,
            LocalResult::None => continue,
        }
    }
    tz.from_utc_datetime(&naive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use grepfocus_core::{
        AllowancePolicy, Block, BreakRecord, LockMode, DAYS_ALL, DAY_MON, DAY_SAT, DAY_TUE,
    };

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

    // ── windows past midnight ───────────────────────────────────────────────

    #[test]
    fn wrap_active_before_midnight_on_start_day() {
        let sch = s(23 * 60, 120, DAY_MON); // Mon 23:00 → Tue 01:00
        let mon = t(23, 30, chrono::Weekday::Mon);
        assert!(schedule_active_at(&sch, &mon));
        assert_eq!(window_start_date_at(&sch, &mon), Some(mon.date_naive()));
        assert!(!schedule_active_at(&sch, &t(22, 59, chrono::Weekday::Mon)));
        // Tuesday night is no instance of a Monday window.
        assert!(!schedule_active_at(&sch, &t(23, 30, chrono::Weekday::Tue)));
    }

    #[test]
    fn wrap_active_after_midnight_only_if_start_day_selected() {
        let sch = s(23 * 60, 120, DAY_MON);
        let tue = t(0, 30, chrono::Weekday::Tue);
        assert!(schedule_active_at(&sch, &tue));
        // The instance belongs to the day it started on.
        assert_eq!(
            window_start_date_at(&sch, &tue),
            Some(t(0, 0, chrono::Weekday::Mon).date_naive())
        );
        // Half-open: 01:00 is out.
        assert!(!schedule_active_at(&sch, &t(1, 0, chrono::Weekday::Tue)));
        // Monday 00:30 would be the tail of a SUNDAY window, not selected.
        assert!(!schedule_active_at(&sch, &t(0, 30, chrono::Weekday::Mon)));
        // Selecting Tuesday instead moves the whole window: Tue 00:30 is
        // then nobody's tail, Wed 00:30 is.
        let tue_only = s(23 * 60, 120, DAY_TUE);
        assert!(!schedule_active_at(&tue_only, &tue));
        assert!(schedule_active_at(
            &tue_only,
            &t(0, 30, chrono::Weekday::Wed)
        ));
    }

    #[test]
    fn wrap_end_is_same_instant_before_and_after_midnight() {
        let sch = s(23 * 60, 120, DAY_MON);
        let end = unix(&t(1, 0, chrono::Weekday::Tue));
        assert_eq!(
            window_end_unix_at(&sch, &t(23, 30, chrono::Weekday::Mon)),
            Some(end)
        );
        assert_eq!(
            window_end_unix_at(&sch, &t(0, 30, chrono::Weekday::Tue)),
            Some(end)
        );
    }

    #[test]
    fn full_day_window_boundary_is_half_open() {
        // 09:00 for 24 h, daily: Tuesday 08:59 is the tail of Monday's
        // instance, Tuesday 09:00 the head of Tuesday's — never both, so one
        // block runs continuously, re-fired once a day at the seam.
        let sch = s(540, 1440, DAYS_ALL);
        let mon = t(0, 0, chrono::Weekday::Mon).date_naive();
        let tue = t(0, 0, chrono::Weekday::Tue).date_naive();
        assert_eq!(
            window_start_date_at(&sch, &t(9, 0, chrono::Weekday::Mon)),
            Some(mon)
        );
        assert_eq!(
            window_start_date_at(&sch, &t(23, 59, chrono::Weekday::Mon)),
            Some(mon)
        );
        assert_eq!(
            window_start_date_at(&sch, &t(0, 0, chrono::Weekday::Tue)),
            Some(mon)
        );
        assert_eq!(
            window_start_date_at(&sch, &t(8, 59, chrono::Weekday::Tue)),
            Some(mon)
        );
        assert_eq!(
            window_start_date_at(&sch, &t(9, 0, chrono::Weekday::Tue)),
            Some(tue)
        );
        // The end follows the instance: Monday's ends as Tuesday's begins.
        let seam = unix(&t(9, 0, chrono::Weekday::Tue));
        assert_eq!(
            window_end_unix_at(&sch, &t(8, 59, chrono::Weekday::Tue)),
            Some(seam)
        );
        assert_eq!(
            window_end_unix_at(&sch, &t(9, 0, chrono::Weekday::Tue)),
            Some(unix(&t(9, 0, chrono::Weekday::Wed)))
        );
        // Monday only: Tuesday 08:59 is still in, 09:00 out.
        let mon_only = s(540, 1440, DAY_MON);
        assert!(schedule_active_at(
            &mon_only,
            &t(8, 59, chrono::Weekday::Tue)
        ));
        assert!(!schedule_active_at(
            &mon_only,
            &t(9, 0, chrono::Weekday::Tue)
        ));
    }

    #[test]
    fn end_at_1440_is_next_day_midnight() {
        // A window ending exactly at 24:00 does not spill over: 00:00 on
        // Tuesday is outside it, and its end instant is that midnight.
        let sch = s(23 * 60, 60, DAY_MON);
        let midnight = unix(&t(0, 0, chrono::Weekday::Tue));
        assert_eq!(
            window_end_unix_at(&sch, &t(23, 30, chrono::Weekday::Mon)),
            Some(midnight)
        );
        assert_eq!(
            window_end_unix_at(&sch, &t(0, 0, chrono::Weekday::Tue)),
            None
        );
        assert_eq!(
            window_start_date_at(&sch, &t(0, 0, chrono::Weekday::Tue)),
            None
        );
    }

    /// A wall-clock instant in Europe/Amsterdam, which springs forward on
    /// 2026-03-29 (02:00 → 03:00) and falls back on 2026-10-25 (03:00 →
    /// 02:00), both Sundays — the two nights the DST tests use. Takes an
    /// existing, unambiguous wall time.
    fn ams(y: i32, mo: u32, d: u32, h: u32, m: u32) -> DateTime<chrono_tz::Tz> {
        chrono_tz::Europe::Amsterdam
            .with_ymd_and_hms(y, mo, d, h, m, 0)
            .single()
            .expect("an existing, unambiguous wall time")
    }

    #[test]
    fn dst_gap_end_keeps_real_duration() {
        // Saturday 23:00 for 3.5 h would end at 02:30 on Sunday 2026-03-29,
        // a wall time Amsterdam skips. The window keeps its real length —
        // 3.5 h after it opened is 03:30 CEST — instead of losing the hour.
        let sch = s(23 * 60, 210, DAY_SAT);
        let opened = ams(2026, 3, 28, 23, 0);
        let now = ams(2026, 3, 28, 23, 30);
        let end = window_end_unix_at(&sch, &now).expect("in window");
        assert_eq!(end, opened.timestamp() as u64 + 210 * 60);
        assert_eq!(end, ams(2026, 3, 29, 3, 30).timestamp() as u64);
        // The same instant from the far side of midnight, before the jump.
        let later = ams(2026, 3, 29, 1, 59);
        assert_eq!(window_end_unix_at(&sch, &later), Some(end));
    }

    #[test]
    fn dst_gap_straddling_window_keeps_real_duration() {
        // Saturday 23:00 for 4 h ends at 03:00 on Sunday 2026-03-29 — a
        // wall time that EXISTS, the first after the jump, so the wall end
        // alone would come an hour short in real time: the skipped hour is
        // inside the window rather than at its end. The window still keeps
        // its real length — 4 h after it opened is 04:00 CEST.
        let sch = s(23 * 60, 240, DAY_SAT);
        let opened = ams(2026, 3, 28, 23, 0);
        let now = ams(2026, 3, 28, 23, 30);
        let end = window_end_unix_at(&sch, &now).expect("in window");
        assert_eq!(end, opened.timestamp() as u64 + 240 * 60);
        assert_eq!(end, ams(2026, 3, 29, 4, 0).timestamp() as u64);
        // The same instant from the far side of midnight, before the jump.
        let later = ams(2026, 3, 29, 1, 59);
        assert_eq!(window_end_unix_at(&sch, &later), Some(end));
    }

    #[test]
    fn dst_overlap_end_prefers_later_instant() {
        // Saturday 23:00 for 3.5 h ends at 02:30 on Sunday 2026-10-25, a
        // wall time Amsterdam shows twice. The later reading wins: the block
        // runs 4.5 real hours, never shorter than configured.
        let sch = s(23 * 60, 210, DAY_SAT);
        let opened = ams(2026, 10, 24, 23, 0);
        let now = ams(2026, 10, 24, 23, 30);
        let end = window_end_unix_at(&sch, &now).expect("in window");
        let later = chrono_tz::Europe::Amsterdam
            .with_ymd_and_hms(2026, 10, 25, 2, 30, 0)
            .latest()
            .unwrap();
        assert_eq!(end, later.timestamp() as u64);
        assert_eq!(end, opened.timestamp() as u64 + 270 * 60);
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

    /// The running block must come out of `reconcile` exactly as it went in:
    /// still the one active, with its snapshotted end, nothing recorded.
    fn assert_still_running(st: &State, changed: bool, ends_at_unix: u64) {
        assert!(!changed);
        assert_eq!(st.active.len(), 1);
        assert_eq!(st.active[0].ends_at_unix, ends_at_unix);
        assert!(matches!(
            st.active[0].originator,
            Originator::Schedule { schedule_id: 1 }
        ));
        assert!(st.stats.sessions.is_empty());
    }

    #[test]
    fn disabled_schedule_does_not_end_its_running_block() {
        // Disabling mid-window is not an escape hatch: the block keeps the
        // window end it snapshotted when it fired.
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let mut st = State::default();
        st.blocks.push(block(0));
        let mut sch = s(540, 60, DAY_MON);
        sch.enabled = false;
        st.schedules.push(sch);
        let ends_at = unix(&t(10, 0, chrono::Weekday::Mon));
        st.active.push(sched_active(0, 1, ends_at));
        let changed = reconcile(
            &mut st,
            now,
            &now_l,
            day_of(&now_l),
            &all_gates(),
            &mut HashSet::new(),
        );
        assert_still_running(&st, changed, ends_at);
    }

    #[test]
    fn deleted_schedule_does_not_end_its_running_block() {
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let mut st = State::default();
        st.blocks.push(block(0));
        // The schedule that fired this block (id 1) is gone from the table.
        let ends_at = unix(&t(10, 0, chrono::Weekday::Mon));
        st.active.push(sched_active(0, 1, ends_at));
        let changed = reconcile(
            &mut st,
            now,
            &now_l,
            day_of(&now_l),
            &all_gates(),
            &mut HashSet::new(),
        );
        assert_still_running(&st, changed, ends_at);
    }

    #[test]
    fn moved_window_does_not_end_its_running_block() {
        // The window was moved to the afternoon while its morning instance
        // runs: `now` is outside the schedule's window, the block stays.
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let mut st = State::default();
        st.blocks.push(block(0));
        st.schedules.push(s(14 * 60, 60, DAY_MON));
        let ends_at = unix(&t(10, 0, chrono::Weekday::Mon));
        st.active.push(sched_active(0, 1, ends_at));
        let changed = reconcile(
            &mut st,
            now,
            &now_l,
            day_of(&now_l),
            &all_gates(),
            &mut HashSet::new(),
        );
        assert_still_running(&st, changed, ends_at);
    }

    #[test]
    fn shortened_schedule_runs_to_snapshotted_end() {
        // 09:00 for 60 min fired (end snapshotted at 10:00); the window is
        // then cut to 30 min. At 09:45 the schedule is out of window and the
        // block runs on; at 10:00 it expires through step 1, once.
        let ends_at = unix(&t(10, 0, chrono::Weekday::Mon));
        let mut st = State::default();
        st.blocks.push(block(0));
        st.schedules.push(s(540, 30, DAY_MON));
        let mut a = sched_active(0, 1, ends_at);
        a.started_at_unix = unix(&t(9, 0, chrono::Weekday::Mon));
        st.active.push(a);

        let mid = t(9, 45, chrono::Weekday::Mon);
        let changed = reconcile(
            &mut st,
            unix(&mid),
            &mid,
            day_of(&mid),
            &all_gates(),
            &mut HashSet::new(),
        );
        assert_still_running(&st, changed, ends_at);

        let end = t(10, 0, chrono::Weekday::Mon);
        let changed = reconcile(
            &mut st,
            unix(&end),
            &end,
            day_of(&end),
            &all_gates(),
            &mut HashSet::new(),
        );
        assert!(changed);
        assert!(st.active.is_empty());
        assert_eq!(st.stats.sessions.len(), 1);
        assert_eq!(st.stats.sessions[0].origin, Origin::Schedule);
        assert_eq!(st.stats.sessions[0].duration_secs, 3600);
    }

    #[test]
    fn extended_schedule_refires_at_snapshotted_end() {
        // 09:00 for 60 min fired (end 10:00); the window is then stretched to
        // 120 min. The running block still ends at 10:00 — one session — and
        // the same tick re-fires the schedule, whose window is still open,
        // as a second active ending at the new 11:00.
        let ends_at = unix(&t(10, 0, chrono::Weekday::Mon));
        let mut st = State::default();
        st.blocks.push(block(0));
        st.schedules.push(s(540, 120, DAY_MON));
        let mut a = sched_active(0, 1, ends_at);
        a.started_at_unix = unix(&t(9, 0, chrono::Weekday::Mon));
        st.active.push(a);

        let end = t(10, 0, chrono::Weekday::Mon);
        let changed = reconcile(
            &mut st,
            unix(&end),
            &end,
            day_of(&end),
            &all_gates(),
            &mut HashSet::new(),
        );
        assert!(changed);
        assert_eq!(st.stats.sessions.len(), 1);
        assert_eq!(st.stats.sessions[0].origin, Origin::Schedule);
        assert_eq!(st.stats.sessions[0].duration_secs, 3600);
        assert_eq!(st.active.len(), 1);
        assert_eq!(st.active[0].started_at_unix, unix(&end));
        assert_eq!(
            st.active[0].ends_at_unix,
            unix(&t(11, 0, chrono::Weekday::Mon))
        );
        assert!(matches!(
            st.active[0].originator,
            Originator::Schedule { schedule_id: 1 }
        ));
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
        // A schedule-started active reaches its snapshotted end → dropped in
        // step 1 like any other, and recorded with a Schedule origin. The
        // schedule is still enabled but out of window, so nothing re-fires.
        let now_l = t(10, 0, chrono::Weekday::Mon);
        let now = unix(&now_l);
        let today = day_of(&now_l);
        let mut st = State::default();
        st.blocks.push(block(0));
        st.schedules.push(s(540, 60, DAY_MON));
        let mut a = sched_active(0, 1, now);
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
        assert!(st.active.is_empty());
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
        // Nothing but its own backstop (step 1) ends a Pomodoro active, and
        // the backstop is in the future. A mid-focus session on reload keeps
        // running and records no false end.
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

    #[test]
    fn skipped_fire_markers_are_pruned_by_the_wall_clock_not_the_block_clock() {
        // 09:30 Monday by the wall clock, with the block clock two hours
        // ahead (a backward step during a running block). A marker for a
        // window that is still open by the wall clock — 10:00 — must survive
        // the tick: pruned against the block clock it would be dropped and
        // the skip re-logged every second. The schedule it names no longer
        // exists, so nothing could re-insert it.
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let wall = unix(&now_l);
        let now = wall + 7_200;
        let mut st = State::default();
        let window_end = wall + 1_800; // 10:00, still ahead by the wall clock
        let mut skipped: HashSet<(u64, u64)> = [(7, window_end)].into_iter().collect();
        reconcile(
            &mut st,
            now,
            &now_l,
            day_of(&now_l),
            &free_gates(),
            &mut skipped,
        );
        assert_eq!(skipped.len(), 1);
    }

    #[test]
    fn schedule_fire_ends_in_the_block_clock_frame() {
        // The block clock sits two hours ahead of the wall clock: a backward
        // `date -s` during a block that is still running, or a clock rolled
        // back across a reboot with a persisted active. The 09:00–10:00
        // window opens by wall time; the block it starts must end thirty
        // minutes of block-clock time later. A wall-instant end (10:00) is
        // already in the past in the block clock's frame: the active would
        // be born expired, dropped on the next tick as a one-second session
        // and fired again, every second until the window closed.
        let now_l = t(9, 30, chrono::Weekday::Mon);
        let wall = unix(&now_l);
        let now = wall + 7_200;
        let mut st = State::default();
        st.blocks.push(block(0));
        st.schedules.push(s(540, 60, DAY_MON));
        let mut skipped = HashSet::new();
        let changed = reconcile(
            &mut st,
            now,
            &now_l,
            day_of(&now_l),
            &all_gates(),
            &mut skipped,
        );
        assert!(changed);
        assert_eq!(st.active.len(), 1);
        assert_eq!(st.active[0].started_at_unix, now);
        assert_eq!(st.active[0].ends_at_unix, now + 1_800);
        // Next tick: the block is still running — nothing expired, nothing
        // re-fired, no session recorded.
        let next_l = now_l + chrono::Duration::seconds(1);
        let changed = reconcile(
            &mut st,
            now + 1,
            &next_l,
            day_of(&next_l),
            &all_gates(),
            &mut skipped,
        );
        assert!(!changed);
        assert_eq!(st.active.len(), 1);
        assert_eq!(st.active[0].ends_at_unix, now + 1_800);
        assert!(st.stats.sessions.is_empty());
        // And it ends when the block clock reaches that end, as one session
        // of the window's remaining length.
        let changed = reconcile(
            &mut st,
            now + 1_800,
            &(now_l + chrono::Duration::seconds(1_800)),
            day_of(&now_l),
            &all_gates(),
            &mut skipped,
        );
        assert!(changed);
        assert!(st.active.is_empty());
        assert_eq!(st.stats.sessions.len(), 1);
        assert_eq!(st.stats.sessions[0].duration_secs, 1_800);
    }

    #[test]
    fn wrap_window_fires_and_expires_across_midnight_in_reconcile() {
        let fire_l = t(23, 30, chrono::Weekday::Mon);
        let fire = unix(&fire_l);
        let mut st = State::default();
        st.blocks.push(block(0));
        st.schedules.push(s(23 * 60, 120, DAY_MON));
        let mut skipped = HashSet::new();
        assert!(reconcile(
            &mut st,
            fire,
            &fire_l,
            day_of(&fire_l),
            &all_gates(),
            &mut skipped
        ));
        assert_eq!(st.active.len(), 1);
        // 90 minutes of the window remain at 23:30: it ends 01:00 Tuesday.
        assert_eq!(st.active[0].ends_at_unix, fire + 5_400);
        // Past midnight the same instance is still running: no re-fire, no
        // expiry, nothing recorded.
        let later_l = fire_l + chrono::Duration::seconds(3_600);
        assert!(!reconcile(
            &mut st,
            fire + 3_600,
            &later_l,
            day_of(&later_l),
            &all_gates(),
            &mut skipped
        ));
        assert_eq!(st.active.len(), 1);
        assert_eq!(st.active[0].ends_at_unix, fire + 5_400);
        assert!(st.stats.sessions.is_empty());
        // At 01:00 it expires as one session of the window's remaining
        // length, and the closed (half-open) window does not fire again.
        let end_l = fire_l + chrono::Duration::seconds(5_400);
        assert!(reconcile(
            &mut st,
            fire + 5_400,
            &end_l,
            day_of(&end_l),
            &all_gates(),
            &mut skipped
        ));
        assert!(st.active.is_empty());
        assert_eq!(st.stats.sessions.len(), 1);
        assert_eq!(st.stats.sessions[0].duration_secs, 5_400);
    }

    #[test]
    fn wrap_skipped_fire_is_logged_once_across_midnight() {
        // Unlicensed: the skip marker is keyed by the window's end, which
        // must read the same on both sides of midnight or the skip would be
        // logged a second time at 00:00.
        let mut st = State::default();
        st.blocks.push(block(0));
        st.schedules.push(s(23 * 60, 120, DAY_MON));
        let mut skipped = HashSet::new();
        for now_l in [
            t(23, 30, chrono::Weekday::Mon),
            t(0, 30, chrono::Weekday::Tue),
        ] {
            reconcile(
                &mut st,
                unix(&now_l),
                &now_l,
                day_of(&now_l),
                &free_gates(),
                &mut skipped,
            );
        }
        assert!(st.active.is_empty());
        // Exactly one marker, keyed by the schedule and the one end instant
        // both ticks computed: Tuesday 01:00.
        assert_eq!(
            skipped,
            HashSet::from([(1, unix(&t(1, 0, chrono::Weekday::Tue)))])
        );
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
