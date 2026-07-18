//! Shared types and helpers for the grepfocus daemon and clients.
//!
//! The wire protocol is length-prefixed JSON: a 4-byte big-endian u32 holding
//! the byte length of the payload, followed by the JSON payload itself.
//! Both directions use the same framing.

use serde::{Deserialize, Serialize};

pub mod hmac_sig;
pub mod license;
pub mod wire;

/// A named bundle of things to block.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Block {
    pub id: u64,
    pub name: String,
    pub domains: Vec<String>,
    pub apps: Vec<AppMatcher>,
    /// Daily "break allowance": total seconds per local day the user may pause
    /// this block while it is active. `0` disables breaks for the block.
    #[serde(default)]
    pub allowance_secs_per_day: u64,
    /// How taking a break is locked down while this block is active.
    /// Non-`Normal` modes are premium, gated when the block is saved.
    /// Defaults to `Normal` for records written before this field existed.
    #[serde(default)]
    pub lock: LockMode,
}

/// How taking a break on an active block is locked down.
///
/// This only concerns blocks that HAVE a break allowance: "no breaks at all"
/// is already free — `Block::allowance_secs_per_day == 0` makes every break
/// request fail and hides the break row in the GUI entirely — so there is
/// deliberately no redundant `NoBreaks` variant here. Do not re-add one.
///
/// Every non-`Normal` mode is a premium feature
/// (`license::features::LOCK_MODES`), enforced when the block is SAVED, not
/// when it runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockMode {
    /// Breaks work as configured (subject to the daily allowance). The only
    /// mode the free tier can save.
    #[default]
    Normal,
    /// A break requires the settings password (an active unlock window).
    PasswordBreaks,
    /// A break requires retyping a random challenge string the daemon issues.
    ChallengeBreaks,
}

/// How to identify a process to kill.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AppMatcher {
    /// Match `/proc/<pid>/exe` resolved path exactly.
    ExePath { path: String },
    /// Match the basename of `/proc/<pid>/exe` (e.g. "steam").
    Basename { name: String },
    /// Match a substring inside `/proc/<pid>/cmdline` (for flatpak/snap wrappers).
    Cmdline { contains: String },
}

/// What caused a block to become active. Affects how it's ended.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Originator {
    /// Started by an explicit `start_block` IPC call.
    Manual,
    /// Started by the recurring-schedule engine.
    Schedule { schedule_id: u64 },
    /// Driven by a pomodoro session (see [`PomodoroSession`]). Behaves like
    /// `Manual` for reconcile — it is not schedule-window-driven, so it is
    /// retained across ticks and ends only by its own `ends_at_unix` (the
    /// set's wall-clock backstop) or an explicit `stop_pomodoro`.
    Pomodoro,
}

/// A block that is currently being enforced.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActiveBlock {
    pub block: Block,
    pub started_at_unix: u64,
    pub ends_at_unix: u64,
    #[serde(default = "default_originator")]
    pub originator: Originator,
    /// If set and `> now`, the block is on a break and not currently enforced.
    /// The block does not end — enforcement resumes when this passes.
    #[serde(default)]
    pub break_until_unix: Option<u64>,
    /// Whether this block's app matchers are enforced (matching processes
    /// killed). Snapshotted at activation from the license's `app_blocking`
    /// feature, so a mid-block license change — in either direction — never
    /// alters a running block's app enforcement. Defaults to `false`: old
    /// records (written before this field existed) and free-tier activations
    /// don't enforce apps.
    #[serde(default)]
    pub apps_enforced: bool,
    /// The block's break lock mode, SNAPSHOTTED at activation from the saved
    /// block — exactly like `apps_enforced`. A mid-block edit or license
    /// change must never soften a running block's break rules; snapshotting
    /// can only ever make a running block *stricter than the current
    /// config*, which is the safe direction. Defaults to `Normal` for old
    /// records written before this field existed.
    #[serde(default)]
    pub lock: LockMode,
}

fn default_originator() -> Originator {
    Originator::Manual
}

/// Per-block record of break time spent on a given local day. Used to enforce
/// the daily break allowance. `day` is days since the Unix epoch in local time.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AllowanceLedger {
    pub block_id: u64,
    pub day: i64,
    pub used_secs: u64,
}

/// A recurring weekly schedule that automatically activates a block during a
/// daily time window on selected weekdays.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Schedule {
    pub id: u64,
    pub name: String,
    pub block_id: u64,
    /// Bitmask of days. Bit 0 = Sunday, bit 1 = Monday, ..., bit 6 = Saturday.
    pub days: u8,
    /// Minute of the day (local time) when the window opens, 0..1440.
    pub start_minute: u16,
    /// Window duration in minutes. Must satisfy `start_minute + duration <= 1440`.
    /// Schedules that would span midnight should be split into two schedules.
    pub duration_minutes: u16,
    pub enabled: bool,
}

/// How a completed focus session was started. Mirrors [`Originator`]'s
/// Manual/Schedule distinction, but WITHOUT the `schedule_id` payload: the
/// stats record only needs to say "the user chose this" vs "a schedule fired
/// it", never which schedule (that row may be long deleted by the time the
/// history is read).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// Started by an explicit `start_block` IPC call.
    #[default]
    Manual,
    /// Started by the recurring-schedule engine.
    Schedule,
    /// Driven by a pomodoro session. Labels the single break-inclusive
    /// [`FocusSession`] a pomodoro set records at its end.
    Pomodoro,
}

impl From<&Originator> for Origin {
    fn from(o: &Originator) -> Self {
        match o {
            Originator::Manual => Origin::Manual,
            Originator::Schedule { .. } => Origin::Schedule,
            Originator::Pomodoro => Origin::Pomodoro,
        }
    }
}

/// One completed focus block: recorded at END (the single choke point is the
/// scheduler's reconcile drop — see the daemon), never at start. `duration_secs`
/// is derived once, at record time, from `ended_at_unix - started_at_unix`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FocusSession {
    pub block_id: u64,
    pub name: String,
    pub started_at_unix: u64,
    pub ended_at_unix: u64,
    pub origin: Origin,
    pub duration_secs: u64,
}

/// Per-local-day rollup — the streak and per-day-chart source. `day` is
/// `num_days_from_ce` in local time, the SAME unit as the allowance ledger's
/// `day`, so both reset at local midnight together.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DayStat {
    pub day: i64,
    /// Summed completed-session duration credited to this day.
    pub focus_secs: u64,
    pub sessions_completed: u32,
    pub breaks_taken: u32,
    pub break_secs: u64,
    pub breaks_refused: u32,
    pub app_kills: u32,
}

/// Lifetime running counters — cheap, never pruned (unlike `days`/`sessions`,
/// which are bounded by retention). Only the totals the GUI headlines carry a
/// lifetime figure; per-day-only counters (breaks taken, break seconds) live
/// solely on [`DayStat`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LifetimeTotals {
    pub focus_secs: u64,
    pub sessions: u64,
    pub app_kills: u64,
    pub breaks_refused: u64,
}

/// Bounded, self-pruning record of the user's focus habit. Lives inside
/// [`State`] (integrity-protected by the same HMAC state file — no second
/// file, no new migration surface) and is bounded by construction: every
/// credit enforces the `sessions` ring cap and the `days` retention window,
/// so the blob can never grow without limit.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UsageStats {
    /// Capped ring of completed focus sessions, newest last. Drop-oldest at
    /// [`UsageStats::SESSIONS_CAP`].
    pub sessions: Vec<FocusSession>,
    /// Per-local-day rollups, kept sorted ascending by `day` and retained to
    /// the last [`UsageStats::DAYS_RETAINED`] days (drop-oldest).
    pub days: Vec<DayStat>,
    /// Lifetime totals — running counters, never pruned.
    pub totals: LifetimeTotals,
}

impl UsageStats {
    /// Most recent focus sessions kept; older ones drop off the front.
    pub const SESSIONS_CAP: usize = 200;
    /// Most recent day rollups kept; older ones drop off the front.
    pub const DAYS_RETAINED: usize = 365;

    /// Find (or insert, keeping `days` sorted ascending) the rollup row for
    /// `day`. Callers must run [`UsageStats::enforce_day_retention`] after any
    /// insert so the window stays bounded.
    fn day_entry(&mut self, day: i64) -> &mut DayStat {
        match self.days.binary_search_by_key(&day, |d| d.day) {
            Ok(i) => &mut self.days[i],
            Err(i) => {
                self.days.insert(
                    i,
                    DayStat {
                        day,
                        ..Default::default()
                    },
                );
                &mut self.days[i]
            }
        }
    }

    /// Drop the oldest day rows once the retention window is exceeded. `days`
    /// is sorted ascending, so the oldest are at the front.
    fn enforce_day_retention(&mut self) {
        if self.days.len() > Self::DAYS_RETAINED {
            let overflow = self.days.len() - Self::DAYS_RETAINED;
            self.days.drain(0..overflow);
        }
    }

    /// Record a completed focus session: append it (ring-capped), credit its
    /// day's `focus_secs`/`sessions_completed`, and bump lifetime totals. The
    /// day is passed in (the local day of `ended_at_unix`) so this stays
    /// clock-free — the caller computes it, exactly as `reconcile` receives
    /// `today`.
    pub fn credit_session(&mut self, session: FocusSession, day: i64) {
        let dur = session.duration_secs;
        self.totals.focus_secs = self.totals.focus_secs.saturating_add(dur);
        self.totals.sessions = self.totals.sessions.saturating_add(1);
        {
            let d = self.day_entry(day);
            d.focus_secs = d.focus_secs.saturating_add(dur);
            d.sessions_completed = d.sessions_completed.saturating_add(1);
        }
        self.enforce_day_retention();
        self.sessions.push(session);
        if self.sessions.len() > Self::SESSIONS_CAP {
            let overflow = self.sessions.len() - Self::SESSIONS_CAP;
            self.sessions.drain(0..overflow);
        }
    }

    /// Credit a break taken (count + seconds) to `day`. No lifetime counter —
    /// breaks taken are a per-day-only figure.
    pub fn credit_break(&mut self, day: i64, secs: u64) {
        let d = self.day_entry(day);
        d.breaks_taken = d.breaks_taken.saturating_add(1);
        d.break_secs = d.break_secs.saturating_add(secs);
        self.enforce_day_retention();
    }

    /// Credit a refused break attempt (a temptation the tool caught) to `day`
    /// and to the lifetime total.
    pub fn credit_break_refused(&mut self, day: i64) {
        {
            let d = self.day_entry(day);
            d.breaks_refused = d.breaks_refused.saturating_add(1);
        }
        self.totals.breaks_refused = self.totals.breaks_refused.saturating_add(1);
        self.enforce_day_retention();
    }

    /// Credit `n` distinct app kills to `day` and to the lifetime total. A
    /// zero drain is a no-op so opportunistic flushes never create empty day
    /// rows.
    pub fn credit_app_kills(&mut self, day: i64, n: u64) {
        if n == 0 {
            return;
        }
        {
            let d = self.day_entry(day);
            d.app_kills = d.app_kills.saturating_add(n as u32);
        }
        self.totals.app_kills = self.totals.app_kills.saturating_add(n);
        self.enforce_day_retention();
    }

    /// Compute `(current, longest)` focus streaks from `days`, treating a day
    /// as "focused" when `sessions_completed > 0`. Pure over `days` + `today`
    /// (never stored — a persisted streak would rot across a restart or a
    /// date change):
    /// * current = the run of consecutive focused days ending TODAY or
    ///   YESTERDAY (today may be mid-progress, so an unfinished today must not
    ///   read as a broken streak);
    /// * longest = the longest such run anywhere in the retained history.
    pub fn compute_streak(&self, today: i64) -> (u32, u32) {
        let active: std::collections::HashSet<i64> = self
            .days
            .iter()
            .filter(|d| d.sessions_completed > 0)
            .map(|d| d.day)
            .collect();

        // Current: anchor on today if it counts, else yesterday, then walk
        // backwards while the run continues.
        let mut current = 0u32;
        let anchor = if active.contains(&today) {
            Some(today)
        } else if active.contains(&(today - 1)) {
            Some(today - 1)
        } else {
            None
        };
        if let Some(mut d) = anchor {
            while active.contains(&d) {
                current = current.saturating_add(1);
                d -= 1;
            }
        }

        // Longest: from each run START (a focused day whose predecessor is
        // not focused) count forward. Every run is visited exactly once.
        let mut longest = 0u32;
        for &d in &active {
            if active.contains(&(d - 1)) {
                continue;
            }
            let mut len = 0u32;
            let mut c = d;
            while active.contains(&c) {
                len = len.saturating_add(1);
                c += 1;
            }
            longest = longest.max(len);
        }

        (current, longest)
    }
}

/// Which half of the pomodoro rhythm a session is currently in.
///
/// A session alternates `Focus` (the block is enforced) and `Break` (the
/// block's `break_until_unix` is set, lifting enforcement without touching
/// the break-allowance ledger). `Default` is `Focus`: a session always opens
/// on a focus interval, and old state that predates this field reads as such.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PomodoroPhase {
    /// The driven block is enforced.
    #[default]
    Focus,
    /// The driven block is on an auto-break; enforcement is lifted.
    Break,
}

/// The phase machine driving ONE saved block through alternating focus/break
/// intervals. Lives in [`State::pomodoro`] and is advanced once per scheduler
/// tick (see the daemon's `advance_pomodoro`). Only one session runs at a
/// time. It reuses the [`ActiveBlock`] identified by `block_id` for
/// enforcement rather than a parallel path: focus enforces, break lifts via
/// that block's `break_until_unix`. Persisted like the block itself, so an
/// in-flight session resumes across a daemon restart.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PomodoroSession {
    /// The saved block this session drives (its [`ActiveBlock`] carries
    /// `Originator::Pomodoro`).
    pub block_id: u64,
    /// Length of each focus interval, in seconds.
    pub focus_secs: u64,
    /// Length of each auto-break between focus intervals, in seconds.
    pub break_secs: u64,
    /// Number of focus intervals in the set.
    pub cycles_total: u32,
    /// 0-based index of the current focus interval.
    pub cycle_index: u32,
    /// Whether the session is mid-focus or mid-break right now.
    pub phase: PomodoroPhase,
    /// Unix time the current phase ends; the tick advances the machine once
    /// `now >= phase_ends_unix`.
    pub phase_ends_unix: u64,
}

/// The running-session view a `Status` response carries so the GUI can render
/// the pomodoro banner and cycle progress. A projection of the live
/// [`PomodoroSession`] (omitting the interval lengths the GUI does not need to
/// redraw); `None` when no session is running.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PomodoroStatus {
    pub block_id: u64,
    pub phase: PomodoroPhase,
    pub phase_ends_unix: u64,
    pub cycle_index: u32,
    pub cycles_total: u32,
}

/// Daemon-side persisted state.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub next_id: u64,
    pub blocks: Vec<Block>,
    /// On-disk format may be `null` (pre-multi-block), `{ ... }` (single
    /// active block, pre-multi-block), or `[ ... ]` (current). All three
    /// are accepted on read; we always write the array form.
    #[serde(default, deserialize_with = "deserialize_active")]
    pub active: Vec<ActiveBlock>,
    #[serde(default)]
    pub schedules: Vec<Schedule>,
    #[serde(default)]
    pub next_schedule_id: u64,
    /// Argon2 PHC hash of the settings password, or `None` if unset.
    /// When set, configuration-changing requests require an active unlock.
    #[serde(default)]
    pub password_hash: Option<String>,
    /// Break-allowance consumption per block per local day.
    #[serde(default)]
    pub allowance: Vec<AllowanceLedger>,
    /// Signed license token exactly as issued by the store, or `None` when
    /// unlicensed. Verified before being stored and again at startup; a token
    /// that no longer verifies (e.g. an expired trial) is kept on disk so
    /// status can report "present but invalid" rather than silently vanishing.
    #[serde(default)]
    pub license_token: Option<String>,
    /// Highest unix time this daemon has ever observed — the clock-rollback
    /// guard for license expiry (see the daemon's `effective_now`). Persisted
    /// opportunistically whenever any other change saves.
    #[serde(default)]
    pub high_water_unix: u64,
    /// Usage-stats record (focus history, per-day rollups, lifetime totals).
    /// Recording is ALWAYS on (cheap, harmless); only the read is license-
    /// gated, so a later purchase reveals prior history. `serde(default)` so
    /// state written before this field existed still loads clean.
    #[serde(default)]
    pub stats: UsageStats,
    /// The in-flight pomodoro session, if one is running. Drives exactly one
    /// active block through focus/break intervals; advanced once per
    /// scheduler tick. `serde(default)` so state written before this field
    /// existed still loads, and an in-flight session persists across a daemon
    /// restart (resumes on reload, like an in-flight block).
    #[serde(default)]
    pub pomodoro: Option<PomodoroSession>,
}

fn deserialize_active<'de, D>(d: D) -> Result<Vec<ActiveBlock>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OldOrNew {
        Many(Vec<ActiveBlock>),
        Single(ActiveBlock),
    }
    let v: Option<OldOrNew> = Option::deserialize(d)?;
    Ok(match v {
        Some(OldOrNew::Many(v)) => v,
        Some(OldOrNew::Single(s)) => vec![s],
        None => Vec::new(),
    })
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Request {
    AddBlock {
        block: Block,
    },
    UpdateBlock {
        block: Block,
    },
    DeleteBlock {
        id: u64,
    },
    ListBlocks {},
    GetStatus {},
    StartBlock {
        id: u64,
        duration_secs: u64,
    },
    /// Rejected while any block is active in strict mode.
    CancelBlock {},
    /// Pause an active block for up to `secs`, capped by its remaining daily
    /// allowance. Does not end the block.
    TakeBreak {
        block_id: u64,
        secs: u64,
        /// Response to the challenge issued by `GetBreakChallenge`. Required
        /// (and verified) only when the active block's lock mode is
        /// `ChallengeBreaks`. Serde default so frames from clients that
        /// predate this field still deserialize.
        #[serde(default)]
        challenge: Option<String>,
    },
    /// Issue a fresh break challenge for an active `ChallengeBreaks` block.
    /// The daemon stores the string it returns and `TakeBreak` must echo it
    /// back — the daemon issues and verifies, so the correct answer never
    /// originates in the (spoofable) GUI.
    GetBreakChallenge {
        block_id: u64,
    },
    AddSchedule {
        schedule: Schedule,
    },
    UpdateSchedule {
        schedule: Schedule,
    },
    DeleteSchedule {
        id: u64,
    },
    ListSchedules {},
    /// Set, change, or clear the settings password. `new: None` clears it.
    /// `old` must match the current password when one is already set
    /// (unless an unlock window is currently active).
    SetPassword {
        old: Option<String>,
        new: Option<String>,
    },
    /// Install (`Some`) or clear (`None`) the license token. The token is
    /// verified before being stored; an invalid token is rejected and
    /// nothing changes. Subject to the same password/unlock gate as other
    /// configuration changes.
    SetLicense {
        token: Option<String>,
    },
    /// Open a time-limited unlock window so configuration changes are allowed.
    Unlock {
        password: String,
    },
    /// Read the usage-stats payload. Gated on the `usage_stats` feature (the
    /// READ only — recording is always on): unlicensed callers get the
    /// feature message.
    GetUsageStats {},
    /// Start a pomodoro session driving block `block_id` through `cycles`
    /// focus intervals of `focus_secs` each, separated by `break_secs`
    /// auto-breaks. Gated on the `pomodoro` feature (activation-time, like
    /// `StartBlock`'s snapshots); refused if a session already runs, the
    /// block is already active or unknown, or the bounds are out of range.
    StartPomodoro {
        block_id: u64,
        focus_secs: u64,
        break_secs: u64,
        cycles: u32,
    },
    /// Stop the running pomodoro session. Hybrid commitment model: allowed
    /// only during a break — refused while a focus interval is in progress.
    /// Ungated (like `TakeBreak`).
    StopPomodoro {},
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Ok {},
    Blocks {
        blocks: Vec<Block>,
    },
    Status {
        active: Vec<ActiveBlock>,
        now_unix: u64,
        /// Whether a settings password is configured.
        #[serde(default)]
        password_set: bool,
        /// Whether configuration changes are currently permitted (no password
        /// set, or an unlock window is active).
        #[serde(default)]
        unlocked: bool,
        /// Today's break-allowance ledger entries for the active blocks, so the
        /// client can show remaining allowance per block.
        #[serde(default)]
        allowance_used: Vec<AllowanceLedger>,
        /// Whether a license token is stored — even one that is currently
        /// invalid or expired (`license_present && !license_valid` is how
        /// the GUI can tell "trial expired" from "never licensed").
        #[serde(default)]
        license_present: bool,
        /// Whether the stored license verified and is unexpired as of this
        /// status (expiry is re-checked at status time, so a trial that
        /// lapses while the daemon runs flips to invalid without a restart).
        #[serde(default)]
        license_valid: bool,
        /// License kind (currently "perpetual" or "trial") from the cached
        /// claims, reported even when the license has expired.
        #[serde(default)]
        license_kind: Option<String>,
        /// Purchaser email from the cached claims.
        #[serde(default)]
        license_email: Option<String>,
        /// Unix seconds; `None` for perpetual licenses or when no claims are
        /// cached. Reported even when expired so the GUI can show since when.
        #[serde(default)]
        license_expires_at: Option<i64>,
        /// Feature keys the license grants (see `license::features`). Only
        /// populated while the license is valid — this drives gating display.
        #[serde(default)]
        licensed_features: Vec<String>,
        /// The running pomodoro session's live view, or `None` when no
        /// session is running. Drives the GUI's Pomodoro banner/progress.
        #[serde(default)]
        pomodoro: Option<PomodoroStatus>,
    },
    Added {
        id: u64,
    },
    Schedules {
        schedules: Vec<Schedule>,
    },
    /// The challenge string issued for a `GetBreakChallenge` request.
    BreakChallenge {
        text: String,
    },
    /// The usage-stats payload for a licensed `GetUsageStats` request.
    /// `sessions` is the stored ring (already capped ~200); `days` is the
    /// recent charting window (last ~30 rollups); `current_streak`/
    /// `longest_streak` are COMPUTED in the read path, never stored.
    UsageStats {
        totals: LifetimeTotals,
        sessions: Vec<FocusSession>,
        days: Vec<DayStat>,
        current_streak: u32,
        longest_streak: u32,
    },
    Error {
        message: String,
    },
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Day-bitmask helpers. Bit 0 = Sunday, 6 = Saturday.
pub const DAY_SUN: u8 = 1 << 0;
pub const DAY_MON: u8 = 1 << 1;
pub const DAY_TUE: u8 = 1 << 2;
pub const DAY_WED: u8 = 1 << 3;
pub const DAY_THU: u8 = 1 << 4;
pub const DAY_FRI: u8 = 1 << 5;
pub const DAY_SAT: u8 = 1 << 6;
pub const DAYS_WEEKDAYS: u8 = DAY_MON | DAY_TUE | DAY_WED | DAY_THU | DAY_FRI;
pub const DAYS_ALL: u8 = 0b0111_1111;

/// True if `days` includes weekday `n` (0=Sun..6=Sat).
pub fn day_set(days: u8, n: u8) -> bool {
    n < 7 && (days & (1 << n)) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Old daemon → new GUI: a Status frame WITHOUT the license fields (what
    // a pre-license daemon emits) must still deserialize; the new fields
    // fall back to their defaults.
    #[test]
    fn status_without_license_fields_still_deserializes() {
        let old = r#"{
            "result": "status",
            "active": [],
            "now_unix": 1752192000,
            "password_set": true,
            "unlocked": false,
            "allowance_used": []
        }"#;
        let resp: Response = serde_json::from_str(old).unwrap();
        match resp {
            Response::Status {
                now_unix,
                password_set,
                license_present,
                license_valid,
                license_kind,
                license_email,
                license_expires_at,
                licensed_features,
                ..
            } => {
                assert_eq!(now_unix, 1752192000);
                assert!(password_set);
                assert!(!license_present);
                assert!(!license_valid);
                assert_eq!(license_kind, None);
                assert_eq!(license_email, None);
                assert_eq!(license_expires_at, None);
                assert!(licensed_features.is_empty());
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    // Pin the wire name: `#[serde(tag = "method", rename_all = "snake_case")]`
    // must turn SetLicense into "set_license", for both install and clear.
    #[test]
    fn set_license_wire_tag_round_trips() {
        let req: Request =
            serde_json::from_str(r#"{"method":"set_license","token":"payload.sig"}"#).unwrap();
        assert!(matches!(
            req,
            Request::SetLicense { token: Some(ref t) } if t == "payload.sig"
        ));

        let req: Request =
            serde_json::from_str(r#"{"method":"set_license","token":null}"#).unwrap();
        assert!(matches!(req, Request::SetLicense { token: None }));

        let json = serde_json::to_string(&Request::SetLicense { token: None }).unwrap();
        assert!(json.contains(r#""method":"set_license""#), "got {json}");
    }

    // ── lock modes (B2.a) ───────────────────────────────────────────────────

    // Old client → new daemon: a TakeBreak frame WITHOUT `challenge` (what
    // every pre-lock-modes GUI/CLI emits) must still deserialize.
    #[test]
    fn take_break_without_challenge_still_deserializes() {
        let req: Request =
            serde_json::from_str(r#"{"method":"take_break","block_id":3,"secs":60}"#).unwrap();
        assert!(matches!(
            req,
            Request::TakeBreak {
                block_id: 3,
                secs: 60,
                challenge: None,
            }
        ));

        let req: Request = serde_json::from_str(
            r#"{"method":"take_break","block_id":3,"secs":60,"challenge":"Abc23"}"#,
        )
        .unwrap();
        assert!(matches!(
            req,
            Request::TakeBreak { challenge: Some(ref c), .. } if c == "Abc23"
        ));
    }

    // Pin the wire names of the new frames: "get_break_challenge" under the
    // "method" tag and "break_challenge" under the "result" tag.
    #[test]
    fn break_challenge_wire_tags_round_trip() {
        let req: Request =
            serde_json::from_str(r#"{"method":"get_break_challenge","block_id":7}"#).unwrap();
        assert!(matches!(req, Request::GetBreakChallenge { block_id: 7 }));
        let json = serde_json::to_string(&Request::GetBreakChallenge { block_id: 7 }).unwrap();
        assert!(
            json.contains(r#""method":"get_break_challenge""#),
            "got {json}"
        );

        let json = serde_json::to_string(&Response::BreakChallenge {
            text: "Abc23".into(),
        })
        .unwrap();
        assert!(json.contains(r#""result":"break_challenge""#), "got {json}");
        let resp: Response = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            resp,
            Response::BreakChallenge { ref text } if text == "Abc23"
        ));
    }

    // Pin LockMode's snake_case wire values.
    #[test]
    fn lock_mode_serializes_snake_case() {
        for (mode, wire) in [
            (LockMode::Normal, r#""normal""#),
            (LockMode::PasswordBreaks, r#""password_breaks""#),
            (LockMode::ChallengeBreaks, r#""challenge_breaks""#),
        ] {
            assert_eq!(serde_json::to_string(&mode).unwrap(), wire);
            assert_eq!(serde_json::from_str::<LockMode>(wire).unwrap(), mode);
        }
    }

    // Old state.json compat: Block and ActiveBlock records written before
    // `lock` existed default to Normal.
    #[test]
    fn block_and_active_block_without_lock_default_to_normal() {
        let block_json = r#"{
            "id": 1,
            "name": "reddit",
            "domains": ["reddit.com"],
            "apps": [],
            "allowance_secs_per_day": 600
        }"#;
        let b: Block = serde_json::from_str(block_json).unwrap();
        assert_eq!(b.lock, LockMode::Normal);

        let active_json = format!(
            r#"{{
                "block": {block_json},
                "started_at_unix": 100,
                "ends_at_unix": 200
            }}"#
        );
        let a: ActiveBlock = serde_json::from_str(&active_json).unwrap();
        assert_eq!(a.lock, LockMode::Normal);
    }

    // ── usage stats (B2.b) ──────────────────────────────────────────────────

    fn session(day_end: u64, dur: u64, origin: Origin) -> FocusSession {
        FocusSession {
            block_id: 1,
            name: "reddit".into(),
            started_at_unix: day_end.saturating_sub(dur),
            ended_at_unix: day_end,
            origin,
            duration_secs: dur,
        }
    }

    #[test]
    fn credit_session_credits_day_and_totals() {
        let mut s = UsageStats::default();
        s.credit_session(session(1000, 300, Origin::Manual), 42);
        s.credit_session(session(2000, 120, Origin::Schedule), 42);
        assert_eq!(s.sessions.len(), 2);
        assert_eq!(s.totals.focus_secs, 420);
        assert_eq!(s.totals.sessions, 2);
        assert_eq!(s.days.len(), 1);
        assert_eq!(s.days[0].day, 42);
        assert_eq!(s.days[0].focus_secs, 420);
        assert_eq!(s.days[0].sessions_completed, 2);
    }

    #[test]
    fn credit_break_and_refused_and_kills() {
        let mut s = UsageStats::default();
        s.credit_break(42, 60);
        s.credit_break(42, 30);
        s.credit_break_refused(42);
        s.credit_app_kills(42, 3);
        s.credit_app_kills(42, 0); // no-op
        let d = &s.days[0];
        assert_eq!(d.breaks_taken, 2);
        assert_eq!(d.break_secs, 90);
        assert_eq!(d.breaks_refused, 1);
        assert_eq!(d.app_kills, 3);
        assert_eq!(s.totals.breaks_refused, 1);
        assert_eq!(s.totals.app_kills, 3);
        // A zero-drain must not have created a second day row.
        assert_eq!(s.days.len(), 1);
    }

    #[test]
    fn days_stay_sorted_and_windowed() {
        let mut s = UsageStats::default();
        // Insert out of order; day_entry keeps them ascending.
        for day in [5, 1, 3, 2, 4] {
            s.credit_break(day, 1);
        }
        let ordered: Vec<i64> = s.days.iter().map(|d| d.day).collect();
        assert_eq!(ordered, vec![1, 2, 3, 4, 5]);

        // Retention drops the oldest beyond the window.
        let mut s = UsageStats::default();
        for day in 0..(UsageStats::DAYS_RETAINED as i64 + 10) {
            s.credit_break(day, 1);
        }
        assert_eq!(s.days.len(), UsageStats::DAYS_RETAINED);
        assert_eq!(s.days.first().unwrap().day, 10); // 0..=9 dropped
    }

    #[test]
    fn sessions_ring_caps_dropping_oldest() {
        let mut s = UsageStats::default();
        let total = UsageStats::SESSIONS_CAP + 5;
        for i in 0..total {
            let mut fs = session(1000 + i as u64, 1, Origin::Manual);
            fs.block_id = i as u64; // tag so we can see which survived
            s.credit_session(fs, 42);
        }
        assert_eq!(s.sessions.len(), UsageStats::SESSIONS_CAP);
        // Oldest five dropped: the first surviving block_id is 5.
        assert_eq!(s.sessions.first().unwrap().block_id, 5);
        assert_eq!(s.sessions.last().unwrap().block_id, (total - 1) as u64);
        // Totals count every session ever, not just the retained ring.
        assert_eq!(s.totals.sessions, total as u64);
    }

    #[test]
    fn streak_today_only() {
        let mut s = UsageStats::default();
        s.credit_session(session(0, 60, Origin::Manual), 100);
        assert_eq!(s.compute_streak(100), (1, 1));
    }

    #[test]
    fn streak_counts_yesterday_when_today_empty() {
        // Today may be mid-progress: a run ending yesterday is still current.
        let mut s = UsageStats::default();
        for day in [98, 99] {
            s.credit_session(session(0, 60, Origin::Manual), day);
        }
        assert_eq!(s.compute_streak(100), (2, 2));
    }

    #[test]
    fn streak_gap_breaks_current_but_longest_persists() {
        let mut s = UsageStats::default();
        // A 3-day run long ago, then a 1-day run ending today.
        for day in [10, 11, 12, 100] {
            s.credit_session(session(0, 60, Origin::Manual), day);
        }
        assert_eq!(s.compute_streak(100), (1, 3));
    }

    #[test]
    fn streak_empty_history_and_stale_run() {
        let s = UsageStats::default();
        assert_eq!(s.compute_streak(100), (0, 0));
        // A run that ended two days ago is no longer current, but is still
        // the longest.
        let mut s = UsageStats::default();
        for day in [96, 97, 98] {
            s.credit_session(session(0, 60, Origin::Manual), day);
        }
        assert_eq!(s.compute_streak(100), (0, 3));
    }

    #[test]
    fn streak_ignores_days_without_completed_sessions() {
        // A day with only a break (no completed session) does not count.
        let mut s = UsageStats::default();
        s.credit_break(100, 60);
        assert_eq!(s.compute_streak(100), (0, 0));
    }

    // Pin the wire names of the new usage-stats frames: "get_usage_stats"
    // under the "method" tag and "usage_stats" under the "result" tag.
    #[test]
    fn usage_stats_wire_tags_round_trip() {
        let req: Request = serde_json::from_str(r#"{"method":"get_usage_stats"}"#).unwrap();
        assert!(matches!(req, Request::GetUsageStats {}));
        let json = serde_json::to_string(&Request::GetUsageStats {}).unwrap();
        assert!(json.contains(r#""method":"get_usage_stats""#), "got {json}");

        let resp = Response::UsageStats {
            totals: LifetimeTotals {
                focus_secs: 420,
                sessions: 2,
                app_kills: 5,
                breaks_refused: 1,
            },
            sessions: vec![session(2000, 120, Origin::Schedule)],
            days: vec![DayStat {
                day: 42,
                focus_secs: 420,
                sessions_completed: 2,
                breaks_taken: 1,
                break_secs: 60,
                breaks_refused: 1,
                app_kills: 5,
            }],
            current_streak: 3,
            longest_streak: 7,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""result":"usage_stats""#), "got {json}");
        let back: Response = serde_json::from_str(&json).unwrap();
        match back {
            Response::UsageStats {
                totals,
                sessions,
                days,
                current_streak,
                longest_streak,
            } => {
                assert_eq!(totals.focus_secs, 420);
                assert_eq!(sessions.len(), 1);
                assert_eq!(sessions[0].origin, Origin::Schedule);
                assert_eq!(days[0].day, 42);
                assert_eq!(current_streak, 3);
                assert_eq!(longest_streak, 7);
            }
            other => panic!("expected UsageStats, got {other:?}"),
        }
    }

    // Old state.json compat: state written before `stats` existed loads with
    // a default (empty) UsageStats.
    #[test]
    fn state_without_stats_field_still_deserializes() {
        let old = r#"{ "next_id": 1, "blocks": [] }"#;
        let st: State = serde_json::from_str(old).unwrap();
        assert!(st.stats.sessions.is_empty());
        assert!(st.stats.days.is_empty());
        assert_eq!(st.stats.totals.sessions, 0);
    }

    // Pin Origin's snake_case wire values.
    #[test]
    fn origin_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&Origin::Manual).unwrap(),
            r#""manual""#
        );
        assert_eq!(
            serde_json::to_string(&Origin::Schedule).unwrap(),
            r#""schedule""#
        );
        assert_eq!(
            Origin::from(&Originator::Schedule { schedule_id: 9 }),
            Origin::Schedule
        );
        assert_eq!(Origin::from(&Originator::Manual), Origin::Manual);
    }

    // ── pomodoro (B2.c) ─────────────────────────────────────────────────────

    // Pin the new Origin/Originator variants' snake_case wire and the
    // Origin::from mapping.
    #[test]
    fn pomodoro_origin_and_originator_wire() {
        assert_eq!(
            serde_json::to_string(&Origin::Pomodoro).unwrap(),
            r#""pomodoro""#
        );
        assert_eq!(Origin::from(&Originator::Pomodoro), Origin::Pomodoro);
        // Unit-like Originator variant under the "kind" tag.
        let json = serde_json::to_string(&Originator::Pomodoro).unwrap();
        assert_eq!(json, r#"{"kind":"pomodoro"}"#);
        let back: Originator = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Originator::Pomodoro);
    }

    // Pin PomodoroPhase's snake_case wire values and Default = Focus.
    #[test]
    fn pomodoro_phase_wire_and_default() {
        assert_eq!(
            serde_json::to_string(&PomodoroPhase::Focus).unwrap(),
            r#""focus""#
        );
        assert_eq!(
            serde_json::to_string(&PomodoroPhase::Break).unwrap(),
            r#""break""#
        );
        assert_eq!(
            serde_json::from_str::<PomodoroPhase>(r#""break""#).unwrap(),
            PomodoroPhase::Break
        );
        assert_eq!(PomodoroPhase::default(), PomodoroPhase::Focus);
    }

    // Pin the wire tags of the new request frames.
    #[test]
    fn pomodoro_request_wire_tags_round_trip() {
        let req: Request = serde_json::from_str(
            r#"{"method":"start_pomodoro","block_id":3,"focus_secs":1500,"break_secs":300,"cycles":4}"#,
        )
        .unwrap();
        assert!(matches!(
            req,
            Request::StartPomodoro {
                block_id: 3,
                focus_secs: 1500,
                break_secs: 300,
                cycles: 4,
            }
        ));
        let json = serde_json::to_string(&Request::StartPomodoro {
            block_id: 3,
            focus_secs: 1500,
            break_secs: 300,
            cycles: 4,
        })
        .unwrap();
        assert!(json.contains(r#""method":"start_pomodoro""#), "got {json}");

        let req: Request = serde_json::from_str(r#"{"method":"stop_pomodoro"}"#).unwrap();
        assert!(matches!(req, Request::StopPomodoro {}));
        let json = serde_json::to_string(&Request::StopPomodoro {}).unwrap();
        assert!(json.contains(r#""method":"stop_pomodoro""#), "got {json}");
    }

    // The Status frame carries the new `pomodoro` field; a Some(..) value
    // round-trips, and old frames without it default to None (covered by
    // `status_without_license_fields_still_deserializes` above via `..`).
    #[test]
    fn status_pomodoro_field_round_trips() {
        let resp = Response::Status {
            active: vec![],
            now_unix: 1000,
            password_set: false,
            unlocked: true,
            allowance_used: vec![],
            license_present: true,
            license_valid: true,
            license_kind: Some("perpetual".into()),
            license_email: None,
            license_expires_at: None,
            licensed_features: vec![],
            pomodoro: Some(PomodoroStatus {
                block_id: 7,
                phase: PomodoroPhase::Break,
                phase_ends_unix: 1300,
                cycle_index: 1,
                cycles_total: 4,
            }),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: Response = serde_json::from_str(&json).unwrap();
        match back {
            Response::Status { pomodoro, .. } => {
                let p = pomodoro.expect("pomodoro present");
                assert_eq!(p.block_id, 7);
                assert_eq!(p.phase, PomodoroPhase::Break);
                assert_eq!(p.phase_ends_unix, 1300);
                assert_eq!(p.cycle_index, 1);
                assert_eq!(p.cycles_total, 4);
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    // A PomodoroSession survives a state round-trip, and old state without
    // the field loads as None (resume-on-restart shape).
    #[test]
    fn state_pomodoro_round_trips_and_defaults_none() {
        let old = r#"{ "next_id": 1, "blocks": [] }"#;
        let st: State = serde_json::from_str(old).unwrap();
        assert!(st.pomodoro.is_none());

        let st = State {
            pomodoro: Some(PomodoroSession {
                block_id: 5,
                focus_secs: 1500,
                break_secs: 300,
                cycles_total: 4,
                cycle_index: 2,
                phase: PomodoroPhase::Focus,
                phase_ends_unix: 9999,
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&st).unwrap();
        let back: State = serde_json::from_str(&json).unwrap();
        let p = back.pomodoro.expect("session present");
        assert_eq!(p.block_id, 5);
        assert_eq!(p.cycle_index, 2);
        assert_eq!(p.cycles_total, 4);
        assert_eq!(p.phase, PomodoroPhase::Focus);
        assert_eq!(p.phase_ends_unix, 9999);
    }
}
