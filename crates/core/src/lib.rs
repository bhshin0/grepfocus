//! Shared types and helpers for the grepfocus daemon and clients.
//!
//! The wire protocol is length-prefixed JSON: a 4-byte big-endian u32 holding
//! the byte length of the payload, followed by the JSON payload itself.
//! Both directions use the same framing.

use std::collections::HashMap;

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
    /// LEGACY daily "break allowance": total seconds per local day the user
    /// may pause this block, `0` meaning no breaks at all.
    ///
    /// Never read this directly — go through [`Block::policy`]. It is kept on
    /// disk purely as a DOWNGRADE MIRROR, refreshed by [`Block::set_policy`],
    /// so a daemon that predates [`AllowancePolicy`] reads a budget that is
    /// never LOOSER than the real policy.
    #[serde(default)]
    pub allowance_secs_per_day: u64,
    /// The break-allowance policy: how much break time this block grants and
    /// over what period. `None` on records written before this field existed
    /// (fall back to the legacy mirror above) AND on records carrying a policy
    /// kind this build does not know — see [`lenient_policy`]. Read it through
    /// [`Block::policy`], which resolves both cases.
    #[serde(default, deserialize_with = "lenient_policy")]
    pub allowance: Option<AllowancePolicy>,
    /// How taking a break is locked down while this block is active.
    /// Non-`Unlocked` modes are premium, gated when the block is saved.
    /// Defaults to `Unlocked` for records written before this field existed.
    #[serde(default)]
    pub lock: LockMode,
}

/// How much break time a block grants, and over what period.
///
/// This is the ALLOWANCE axis — *how much*. It is deliberately separate from
/// the LOCK axis ([`LockMode`], *how hard is it to start a break*): friction is
/// a lock, duration is an allowance. Policies are either/or by construction and
/// never stack, which is why this is a discriminated enum rather than a bag of
/// optional numeric fields. Free tier.
///
/// Internally tagged on `kind`, following the [`AppMatcher`] precedent in this
/// file. Because an internally-tagged enum hard-errors on an unknown tag, the
/// field that carries one on [`Block`] is read through [`lenient_policy`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AllowancePolicy {
    /// No breaks at all. Wire name `"none"`; the Rust name avoids colliding
    /// with `Option::None` at every match site.
    #[default]
    #[serde(rename = "none")]
    Disabled,
    /// `secs` per LOCAL day. What every pre-policy block folds into.
    PerDay { secs: u64 },
    /// At most `secs` within any trailing `window_secs`. The rolling form is
    /// chosen over fixed clock slots because slots don't deliver what "5 min
    /// per hour" promises: 5 min at 09:58 plus 5 min at 10:00 is ten
    /// consecutive minutes within the rules — precisely the boundary a
    /// motivated user learns to wait for.
    ///
    /// The only policy that needs break history.
    RollingWindow { secs: u64, window_secs: u64 },
    /// Every break is exactly `secs`, with no cumulative cap — the friction is
    /// the LOCK ([`LockMode`]), not the allowance. Consults no history at all.
    PerBreak { secs: u64 },
}

/// Deserialize [`Block::allowance`], degrading a policy kind this build does
/// not know to `None` instead of erroring.
///
/// An internally-tagged enum hard-errors on an unknown tag, which would make
/// state written by a NEWER daemon fail to load — and since the
/// verified-but-unparseable state file became fatal at startup, that would take
/// the whole daemon down after a downgrade rather than just one field. So an
/// unrecognized policy degrades to `None` and the block falls back to its
/// legacy `allowance_secs_per_day` mirror, which is never looser than the real
/// policy. Same doctrine as [`deserialize_active`].
fn lenient_policy<'de, D>(d: D) -> Result<Option<AllowancePolicy>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum KnownOrNot {
        Known(AllowancePolicy),
        /// Anything else that is still valid JSON — a future `kind`, or a
        /// malformed payload. Swallowed, never surfaced; the payload is
        /// captured only so that serde has somewhere to put it.
        Unknown(#[allow(dead_code)] serde_json::Value),
    }
    let v: Option<KnownOrNot> = Option::deserialize(d)?;
    Ok(match v {
        Some(KnownOrNot::Known(p)) => Some(p),
        Some(KnownOrNot::Unknown(_)) | None => None,
    })
}

impl Block {
    /// The block's effective break-allowance policy.
    ///
    /// The SINGLE reader of `allowance_secs_per_day`: an explicit policy wins,
    /// otherwise the legacy scalar folds into `PerDay` (or `Disabled` at `0`,
    /// which is how "no breaks" has always been encoded).
    pub fn policy(&self) -> AllowancePolicy {
        match &self.allowance {
            Some(p) => p.clone(),
            None if self.allowance_secs_per_day > 0 => AllowancePolicy::PerDay {
                secs: self.allowance_secs_per_day,
            },
            None => AllowancePolicy::Disabled,
        }
    }

    /// Set the policy AND refresh the legacy downgrade mirror, so the two can
    /// never drift.
    ///
    /// For `RollingWindow`, mirroring the per-window budget means an older
    /// daemon enforces that budget per DAY instead — strictly stricter, which
    /// is the only safe direction for a downgrade.
    pub fn set_policy(&mut self, p: AllowancePolicy) {
        self.allowance_secs_per_day = match &p {
            AllowancePolicy::Disabled => 0,
            AllowancePolicy::PerDay { secs }
            | AllowancePolicy::RollingWindow { secs, .. }
            | AllowancePolicy::PerBreak { secs } => *secs,
        };
        self.allowance = Some(p);
    }
}

/// How taking a break on an active block is locked down.
///
/// This only concerns blocks that HAVE a break allowance: "no breaks at all"
/// is already free — `Block::allowance_secs_per_day == 0` makes every break
/// request fail and hides the break row in the GUI entirely — so there is
/// deliberately no redundant `NoBreaks` variant here. Do not re-add one.
///
/// Every non-`Unlocked` mode is a premium feature
/// (`license::features::LOCK_MODES`), enforced when the block is SAVED, not
/// when it runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockMode {
    /// No lock: breaks work as configured (subject to the daily allowance).
    /// The only mode the free tier can save.
    ///
    /// The wire value stays `"normal"` — released daemons deserialize
    /// `LockMode` as a bare string with no unknown-variant fallback, so a
    /// state file saying `"unlocked"` would be unreadable to them, and an
    /// unreadable-but-verified state file is fatal at startup.
    #[default]
    #[serde(rename = "normal")]
    Unlocked,
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
    /// config*, which is the safe direction. Defaults to `Unlocked` for old
    /// records written before this field existed.
    #[serde(default)]
    pub lock: LockMode,
    /// The block's break-allowance policy, SNAPSHOTTED at activation from the
    /// saved block — exactly like `apps_enforced` and `lock`. A mid-block edit
    /// must never change a running block's break budget. `None` on records
    /// written before this field existed; read via [`ActiveBlock::policy`],
    /// which falls back to the embedded block.
    #[serde(default)]
    pub allowance: Option<AllowancePolicy>,
}

impl ActiveBlock {
    /// The policy this running block is actually granted under.
    ///
    /// Prefers the activation snapshot and falls back to the embedded block's
    /// own policy, which is what a record written before the snapshot existed
    /// carries — and which, for such a record, IS the policy that was in force
    /// at activation, since a block cannot be edited while active.
    pub fn policy(&self) -> AllowancePolicy {
        self.allowance
            .clone()
            .unwrap_or_else(|| self.block.policy())
    }
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

/// One break that was taken: the unit of break history.
///
/// This supersedes [`AllowanceLedger`], which was a per-day counter. Every
/// allowance policy is a reducer over history, and history is a strict
/// superset of a counter — a per-day sum is one `filter` away, while a rolling
/// window cannot be recovered from a counter at all.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakRecord {
    pub block_id: u64,
    /// Unix time the break STARTED — the bucketing key for window policies.
    /// Bucketing by start (not end) keeps usage monotone as `now` advances.
    pub start_unix: u64,
    pub secs: u64,
    /// Local day of `start_unix`, STORED rather than derived: per-day
    /// bucketing is timezone-dependent and every reducer here must stay
    /// clock-free (the caller passes `today` in, exactly as `reconcile`
    /// already does). Deriving it would let a DST change retroactively
    /// re-bucket an already-charged break.
    pub day: i64,
}

/// Longest trailing window any allowance policy may look back over, and
/// therefore how far break history ever needs to reach. Validated at save
/// time, so retention can prune anything older with no policy able to notice.
pub const MAX_ALLOWANCE_WINDOW_SECS: u64 = 24 * 3600;

/// Hard cap on retained [`BreakRecord`]s **per block**, mirroring
/// [`UsageStats::SESSIONS_CAP`].
///
/// History is one row per break, not one per block per day, so this is only
/// reachable by a non-GUI client spamming 1-second breaks. Dropping the oldest
/// rows LOOSENS enforcement (forgotten spend reads as unspent), so this is a
/// memory backstop, not a policy — the real bound is the window filter.
///
/// The cap is applied PER BLOCK rather than to the history as a whole, because
/// a global cap makes one block's churn evict another block's spend. A
/// `PerBreak` block never depletes, so a scripted client can loop 1-second
/// breaks against it forever; under a global cap those rows push a *different*
/// block's exhausted `PerDay` records out of the file, and that block silently
/// gets its budget back. Blockwise, the blast radius of the loosening is the
/// block that caused it.
///
/// The overall bound is therefore `BREAKS_CAP × (distinct block ids present)`.
/// That is still a bound: block ids in history only come from blocks the user
/// created, so the multiplier grows by deliberate UI action, whereas the row
/// count per block grows as fast as a client can call `take_break`. The
/// unbounded axis is the one that is capped.
pub const BREAKS_CAP: usize = 4000;

/// What a [`prune_breaks`] pass removed, split by REASON.
///
/// The split is the point. Window pruning is routine and expected — records
/// aged out of every policy's reach. Cap eviction is not: it drops records a
/// policy could still have counted, which hands allowance back. The caller
/// (the daemon) logs the second and ignores the first, and it can only do that
/// if the two arrive separately. Kept `tracing`-free so core stays pure: this
/// type is the arithmetic, the logging happens where the logger lives.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PruneOutcome {
    /// Records dropped because no policy could still see them. Harmless.
    pub window_dropped: usize,
    /// `(block_id, evicted)` for every block that overflowed [`BREAKS_CAP`],
    /// ascending by id. Non-empty means enforcement was loosened for those
    /// blocks and somebody should hear about it.
    pub cap_evicted: Vec<(u64, usize)>,
}

impl PruneOutcome {
    /// Total records the CAP evicted, across all blocks.
    pub fn cap_evicted_total(&self) -> usize {
        self.cap_evicted.iter().map(|(_, n)| n).sum()
    }

    /// Whether this pass removed anything at all — i.e. whether the state
    /// needs saving.
    pub fn removed_any(&self) -> bool {
        self.window_dropped > 0 || !self.cap_evicted.is_empty()
    }
}

/// Drop break records no policy can still see, then enforce [`BREAKS_CAP`]
/// per block. Reports what each half removed.
///
/// A record is retained when it is either still relevant to a per-day policy
/// (`day == today`) or still inside the longest permitted trailing window.
/// Both conditions are needed: today's rows can be older than the window
/// (early-morning breaks late in the day), and yesterday's rows can still be
/// inside it (a break just before local midnight).
///
/// Relative order is preserved, and within a block the OLDEST rows are the
/// ones evicted — records are appended in start order, so position is age.
///
/// Pure — `now` and `today` are supplied by the caller, and nothing here logs.
pub fn prune_breaks(
    breaks: &mut Vec<BreakRecord>,
    now: u64,
    today: i64,
    max_window: u64,
) -> PruneOutcome {
    let horizon = now.saturating_sub(max_window);
    let before = breaks.len();
    breaks.retain(|r| r.day == today || r.start_unix > horizon);
    let window_dropped = before - breaks.len();

    // How many rows each block has left, and hence how many of its oldest
    // must go. Two passes rather than one so the eviction budget is known
    // before any row is examined for removal.
    let mut per_block: HashMap<u64, usize> = HashMap::new();
    for r in breaks.iter() {
        *per_block.entry(r.block_id).or_default() += 1;
    }
    let mut to_evict: HashMap<u64, usize> = per_block
        .into_iter()
        .filter(|&(_, n)| n > BREAKS_CAP)
        .map(|(id, n)| (id, n - BREAKS_CAP))
        .collect();
    if to_evict.is_empty() {
        return PruneOutcome {
            window_dropped,
            cap_evicted: Vec::new(),
        };
    }

    let mut cap_evicted: Vec<(u64, usize)> = to_evict.iter().map(|(&id, &n)| (id, n)).collect();
    cap_evicted.sort_unstable();

    breaks.retain(|r| match to_evict.get_mut(&r.block_id) {
        Some(left) if *left > 0 => {
            *left -= 1;
            false
        }
        _ => true,
    });

    PruneOutcome {
        window_dropped,
        cap_evicted,
    }
}

/// What a policy currently grants a block: the reduction of break history
/// under an [`AllowancePolicy`], at one instant.
///
/// Computed by [`evaluate_allowance`] and shared by every consumer, so the
/// status read and the break grant can never disagree about what is left.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowanceView {
    /// The policy's budget per its own period. `0` means breaks are off.
    pub budget_secs: u64,
    /// How much of that budget is available right now.
    pub remaining_secs: u64,
    /// When more allowance appears, for the policies where that is a knowable
    /// instant. `None` for `Disabled`, for `PerDay` (local midnight — the
    /// client says "tomorrow" without needing a timestamp) and for `PerBreak`
    /// (which never depletes).
    pub next_free_unix: Option<u64>,
    /// How much allowance returns at `next_free_unix`, ties summed. `0`
    /// whenever `next_free_unix` is `None`. Required to render "3 min now,
    /// 2 more at 10:14" — the instant alone cannot say how much.
    pub next_free_secs: u64,
}

/// One block's allowance, as reported by `GetStatus` — one entry per block id,
/// active or not.
///
/// Inactive blocks are included because a rolling window's consumption outlives
/// the run that spent it: a block can be stopped and restarted and still have
/// nothing available, which a client cannot infer from the configured budget
/// alone.
///
/// The daemon computes this so raw break history never reaches a client and
/// window arithmetic is never reimplemented outside core. It supersedes the
/// deprecated `Response::Status::allowance_used`, which is a bare per-day
/// counter, is emitted only for active blocks, and cannot express a rolling
/// window at all.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowanceStatus {
    pub block_id: u64,
    /// For an ACTIVE block, the activation snapshot's policy — what the running
    /// block will actually be granted under, not the (editable) saved config.
    /// For an inactive block there is no snapshot, so this is the saved
    /// block's policy: what it would activate under.
    pub policy: AllowancePolicy,
    /// Flattened, so the view's fields sit directly alongside `block_id` and
    /// `policy` on the wire rather than nested under a `view` key.
    #[serde(flatten)]
    pub view: AllowanceView,
}

/// Reduce break history under a policy. Pure: `now` and `today` are supplied
/// by the caller, exactly as `reconcile` already does.
///
/// Lives in core rather than the daemon because the status read needs the same
/// arithmetic as the break grant — the [`UsageStats::compute_streak`]
/// precedent for pure reducers over persisted history.
pub fn evaluate_allowance(
    policy: &AllowancePolicy,
    breaks: &[BreakRecord],
    block_id: u64,
    now: u64,
    today: i64,
) -> AllowanceView {
    match *policy {
        AllowancePolicy::Disabled => AllowanceView::default(),

        AllowancePolicy::PerDay { secs } => {
            let used: u64 = breaks
                .iter()
                .filter(|r| r.block_id == block_id && r.day == today)
                .map(|r| r.secs)
                .sum();
            AllowanceView {
                budget_secs: secs,
                remaining_secs: secs.saturating_sub(used),
                next_free_unix: None,
                next_free_secs: 0,
            }
        }

        // Consults no history at all: every break is the same size, and the
        // friction that makes that meaningful is the LOCK, not the budget.
        AllowancePolicy::PerBreak { secs } => AllowanceView {
            budget_secs: secs,
            remaining_secs: secs,
            next_free_unix: None,
            next_free_secs: 0,
        },

        AllowancePolicy::RollingWindow { secs, window_secs } => {
            // Saturating: a backwards clock jump must not underflow into a
            // horizon near u64::MAX, which would count nothing and hand out
            // free allowance.
            let horizon = now.saturating_sub(window_secs);
            // Strict `>`: a record sitting exactly on the boundary has left
            // the window. This is also what keeps legacy `start_unix == 0`
            // rows (see `State::absorb_legacy_allowance`) out of every window.
            let counted = breaks
                .iter()
                .filter(|r| r.block_id == block_id && r.start_unix > horizon);

            let mut used = 0u64;
            let mut next_free_unix: Option<u64> = None;
            let mut next_free_secs = 0u64;
            for r in counted {
                used = used.saturating_add(r.secs);
                // The oldest counted record is the first to age out, and it
                // frees its own `secs` when it does. Ties sum.
                let expires = r.start_unix.saturating_add(window_secs);
                match next_free_unix {
                    Some(e) if e < expires => {}
                    Some(e) if e == expires => next_free_secs += r.secs,
                    _ => {
                        next_free_unix = Some(expires);
                        next_free_secs = r.secs;
                    }
                }
            }
            let remaining_secs = secs.saturating_sub(used);
            // Clamp to what the policy is actually WITHHOLDING right now:
            // `budget - remaining`, i.e. `min(used, budget)`. Nothing can
            // "return" that the policy is not currently taking away — after
            // the oldest records age out, remaining is still capped at the
            // budget, so the most it can ever rise by is the gap below it.
            //
            // The raw sum of expiring records can exceed that gap, and this is
            // reachable in practice: a block spends 900s under
            // `PerDay { 900 }`, the user then edits it to
            // `RollingWindow { secs: 300, window_secs: 3600 }` and it restarts
            // inside the hour. The 900s record is in the new window, so the
            // untrimmed figure claims 15 minutes return against a 5-minute
            // budget, and the GUI renders that verbatim. Under a stable policy
            // this is unreachable (grants are capped at `remaining` and
            // records only ever leave the window) — but a policy edit between
            // runs is a supported thing to do, so the ceiling is enforced
            // rather than assumed.
            //
            // `budget - remaining` is chosen over the looser `budget` because
            // it is also correct in the ordinary case: with 100s spent of a
            // 300s budget, at most 100s can come back, never 300s.
            let next_free_secs = next_free_secs.min(secs.saturating_sub(remaining_secs));
            AllowanceView {
                budget_secs: secs,
                remaining_secs,
                next_free_unix,
                next_free_secs,
            }
        }
    }
}

/// Compute the grantable break length (seconds) for a break request, capped by
/// both the policy's remaining allowance and the block's remaining time.
///
/// The four checks run in this order deliberately: it is the order the daily
/// allowance has always used, so the accept path and every error string stay
/// byte-identical for `PerDay` blocks.
pub fn compute_grant(
    policy: &AllowancePolicy,
    breaks: &[BreakRecord],
    block_id: u64,
    ends_at: u64,
    now: u64,
    today: i64,
    requested: u64,
) -> Result<u64, &'static str> {
    let view = evaluate_allowance(policy, breaks, block_id, now, today);
    if view.budget_secs == 0 {
        return Err("this block has no break allowance");
    }
    if view.remaining_secs == 0 {
        // Deliberately clock-free wording on the rolling arm: saying "until
        // 10:14" here would drag `chrono::Local` into a pure helper. The
        // client formats `AllowanceView::next_free_unix` itself.
        return Err(match policy {
            AllowancePolicy::RollingWindow { .. } => {
                "no break allowance left in the current window"
            }
            _ => "no break allowance left today",
        });
    }
    // A break can never outlive the block, so never charge for time past its end.
    if ends_at <= now {
        return Err("this block has already ended");
    }
    let grant = requested.min(view.remaining_secs).min(ends_at - now);
    if grant == 0 {
        return Err("break length must be at least 1 second");
    }
    Ok(grant)
}

/// Reject policies that cannot mean anything useful, returning a user-facing
/// message. `None` means the policy is saveable.
pub fn validate_policy(p: &AllowancePolicy) -> Option<&'static str> {
    match *p {
        AllowancePolicy::Disabled => None,
        AllowancePolicy::PerDay { secs } | AllowancePolicy::PerBreak { secs } => {
            // A zero budget on a policy that claims to grant breaks is a
            // configuration mistake; "no breaks" has its own kind.
            if secs == 0 {
                return Some("break allowance must be at least 1 second — choose \"no breaks\" to disable breaks entirely");
            }
            if secs > 24 * 3600 {
                return Some("break allowance cannot exceed 24 hours");
            }
            None
        }
        AllowancePolicy::RollingWindow { secs, window_secs } => {
            if secs == 0 {
                return Some("break allowance must be at least 1 second — choose \"no breaks\" to disable breaks entirely");
            }
            // Bounded above by how far break history is retained, and below by
            // a minute so the window is something a person can perceive.
            if !(60..=MAX_ALLOWANCE_WINDOW_SECS).contains(&window_secs) {
                return Some("break window must be between 1 minute and 24 hours");
            }
            // A budget larger than its own window can never bind — the window
            // would expire before the budget could be spent.
            if secs > window_secs {
                return Some("break allowance cannot exceed its own window");
            }
            None
        }
    }
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

/// Cross-cutting user preferences — the settings that are not per-block.
///
/// Persisted in [`State`] and echoed on `Status` so the GUI can render the
/// current values without a second round trip. `#[serde(default)]` at the
/// container level so a partial object (`{}`, or a future daemon's extra
/// fields stripped) fills every missing field from [`Settings::default`]
/// rather than from serde's per-field zero value — which for a `bool` would
/// be `false`, the wrong default here (see the hand-written `Default`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Desktop notifications (block start/end). Default ON, preserving
    /// today's behaviour.
    pub notifications: bool,
    /// Point blocked domains at `127.0.0.1` and hold a loopback proxy there
    /// while any block is active, so a blocked connection is refused instantly
    /// by our own listener instead of resolving to a dark `0.0.0.0`. Default
    /// ON. Read only by `enforce`; toggling it is a later stage.
    ///
    /// Like `notifications`, the hand-written [`Default`] below sets this
    /// `true`, so an old state file whose `settings` object predates the field
    /// fills it from the default (ON) rather than from serde's bool zero
    /// (OFF) — see the container-level `#[serde(default)]`.
    pub instant_breaks: bool,
}

impl Default for Settings {
    /// HAND-WRITTEN, deliberately not `#[derive(Default)]`: derive would give
    /// every `bool` `false`, silently disabling both notifications and
    /// instant-breaks for every existing user the moment they upgrade to a
    /// daemon that reads these fields. The default must preserve the
    /// pre-settings behaviour, which was notifications always on, and match
    /// the on-by-default intent of instant-breaks.
    fn default() -> Self {
        Self {
            notifications: true,
            instant_breaks: true,
        }
    }
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
    /// LEGACY break-allowance consumption per block per local day. Superseded
    /// by `breaks`, but RETAINED as a field: an old ledger row cannot
    /// deserialize into a [`BreakRecord`], and one failing element fails the
    /// whole `State`. Folded once by [`State::absorb_legacy_allowance`].
    #[serde(default)]
    pub allowance: Vec<AllowanceLedger>,
    /// Break history — the source every allowance policy reduces over. A NEW
    /// field rather than a reinterpretation of `allowance`, for the reason
    /// given there. `serde(default)` so state written before it existed loads.
    #[serde(default)]
    pub breaks: Vec<BreakRecord>,
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
    /// Cross-cutting user preferences. `serde(default)` so state written
    /// before this field existed loads with the hand-written [`Settings`]
    /// default (notifications on), never with a zeroed one.
    #[serde(default)]
    pub settings: Settings,
}

impl State {
    /// Fold the legacy per-day allowance ledger into break history, once.
    ///
    /// Each ledger row becomes a single record carrying that day's whole spend.
    /// `start_unix` is `0` — arbitrarily ancient — so the row can never count
    /// against a rolling window it has no timing information for, while `day`
    /// preserves per-day spend exactly. That is the conservative direction on
    /// the only axis where the data is genuinely missing.
    ///
    /// Idempotent: it drains `allowance`, so a second call is a no-op.
    pub fn absorb_legacy_allowance(&mut self) {
        for row in self.allowance.drain(..) {
            self.breaks.push(BreakRecord {
                block_id: row.block_id,
                start_unix: 0,
                secs: row.used_secs,
                day: row.day,
            });
        }
    }
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
    /// Replace the cross-cutting user preferences wholesale. Subject to the
    /// settings-lock discipline (like other config changes), but NOT license
    /// gated — preferences are free.
    SetSettings {
        settings: Settings,
    },
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
        /// DEPRECATED: today's break-allowance ledger entries for the active
        /// blocks. Superseded by `allowance`, which carries the policy and a
        /// full [`AllowanceView`]; this is now DERIVED from break history
        /// (today's rows summed per active block) purely so a client built
        /// against a pre-policy daemon keeps rendering identical numbers. New
        /// clients must read `allowance`. Do not remove.
        #[serde(default)]
        allowance_used: Vec<AllowanceLedger>,
        /// One entry per SAVED block, plus any active block (there is exactly
        /// one entry per block id). An active block reports its
        /// activation-snapshot policy; an inactive one reports its saved
        /// policy, so a client can see that a rolling window spent during an
        /// earlier run is still depleted. `#[serde(default)]` matters in the
        /// other direction too: a NEW client talking to an OLD daemon must get
        /// an empty vec and fall back to `allowance_used`, not a parse error.
        #[serde(default)]
        allowance: Vec<AllowanceStatus>,
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
        /// Current cross-cutting preferences, so the GUI reads them off the
        /// same status poll it already makes. `#[serde(default)]` in both
        /// directions: an old daemon that never emits it leaves the client
        /// with the hand-written default (notifications on), and a partial
        /// object fills the same way.
        #[serde(default)]
        settings: Settings,
        /// True when `settings.instant_breaks` is on and a block is active but
        /// the loopback proxy could not bind both ports, so breaks lag on this
        /// machine. Drives a GUI notice explaining why. `#[serde(default)]`:
        /// an old daemon never emits it and the client reads `false`.
        #[serde(default)]
        instant_breaks_degraded: bool,
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

    // Records written before the snapshot existed carry no `allowance`, and
    // must fall back to the embedded block's policy — which for such a record
    // IS what was in force at activation, since a block cannot be edited while
    // active.
    #[test]
    fn active_block_without_allowance_falls_back_to_the_block() {
        let old = r#"{
            "block": {
                "id": 1,
                "name": "reddit",
                "domains": ["reddit.com"],
                "apps": [],
                "allowance_secs_per_day": 600,
                "lock": "normal"
            },
            "started_at_unix": 1000,
            "ends_at_unix": 2000
        }"#;
        let a: ActiveBlock = serde_json::from_str(old).unwrap();
        assert_eq!(a.allowance, None);
        assert_eq!(a.policy(), AllowancePolicy::PerDay { secs: 600 });
    }

    // The snapshot WINS over the embedded block: that is the entire point.
    // Editing the saved block cannot retroactively change the budget a
    // running block has already been spending against.
    #[test]
    fn active_block_snapshot_beats_a_later_block_edit() {
        let mut block = Block {
            id: 1,
            name: "reddit".into(),
            domains: vec![],
            apps: vec![],
            allowance_secs_per_day: 0,
            allowance: None,
            lock: LockMode::Unlocked,
        };
        block.set_policy(AllowancePolicy::PerDay { secs: 600 });
        let mut a = ActiveBlock {
            allowance: Some(block.policy()),
            block,
            started_at_unix: 1000,
            ends_at_unix: 2000,
            originator: Originator::Manual,
            break_until_unix: None,
            apps_enforced: false,
            lock: LockMode::Unlocked,
        };
        // Simulate a mid-block edit landing on the embedded block.
        a.block.set_policy(AllowancePolicy::PerDay { secs: 36_000 });
        assert_eq!(a.policy(), AllowancePolicy::PerDay { secs: 600 });
        assert_eq!(a.block.policy(), AllowancePolicy::PerDay { secs: 36_000 });
    }

    // New GUI → OLD daemon: a Status frame without `allowance` must still
    // deserialize to an empty vec, so the client can fall back to the
    // deprecated `allowance_used` instead of failing the whole read.
    #[test]
    fn status_without_allowance_still_deserializes() {
        let old = r#"{
            "result": "status",
            "active": [],
            "now_unix": 1752192000,
            "password_set": false,
            "unlocked": true,
            "allowance_used": [{"block_id": 7, "day": 20000, "used_secs": 120}]
        }"#;
        let resp: Response = serde_json::from_str(old).unwrap();
        match resp {
            Response::Status {
                allowance,
                allowance_used,
                ..
            } => {
                assert!(allowance.is_empty());
                assert_eq!(allowance_used.len(), 1);
                assert_eq!(allowance_used[0].used_secs, 120);
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    // Pin the FLATTENED field names: the view's fields must sit directly
    // alongside block_id/policy, not nested under a "view" key. A client reads
    // `s.remaining_secs`, so renaming or nesting them is a wire break.
    #[test]
    fn allowance_status_flattens_the_view() {
        let s = AllowanceStatus {
            block_id: 7,
            policy: AllowancePolicy::RollingWindow {
                secs: 300,
                window_secs: 3600,
            },
            view: AllowanceView {
                budget_secs: 300,
                remaining_secs: 120,
                next_free_unix: Some(1752192000),
                next_free_secs: 180,
            },
        };
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["block_id"], 7);
        assert_eq!(json["policy"]["kind"], "rolling_window");
        assert_eq!(json["budget_secs"], 300);
        assert_eq!(json["remaining_secs"], 120);
        assert_eq!(json["next_free_unix"], 1752192000u64);
        assert_eq!(json["next_free_secs"], 180);
        assert!(json.get("view").is_none(), "view must be flattened");
        let back: AllowanceStatus = serde_json::from_value(json).unwrap();
        assert_eq!(back, s);
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

    // ── settings ────────────────────────────────────────────────────────────

    // The load-bearing default: notifications are ON. A #[derive(Default)]
    // here would give `false` and silently mute every upgrading user.
    #[test]
    fn settings_default_has_notifications_on() {
        assert!(Settings::default().notifications);
    }

    // Old state.json compat: a State written before `settings` existed must
    // load with notifications ON, not the bool zero value.
    #[test]
    fn state_without_settings_defaults_notifications_on() {
        let old = r#"{
            "next_id": 1,
            "blocks": [],
            "active": []
        }"#;
        let st: State = serde_json::from_str(old).unwrap();
        assert!(st.settings.notifications);
    }

    // A Status frame without `settings` (old daemon → new GUI) still
    // deserializes, and the missing field fills to the ON default.
    #[test]
    fn status_without_settings_still_deserializes() {
        let old = r#"{
            "result": "status",
            "active": [],
            "now_unix": 1752192000,
            "password_set": false,
            "unlocked": true,
            "allowance_used": []
        }"#;
        let resp: Response = serde_json::from_str(old).unwrap();
        match resp {
            Response::Status { settings, .. } => assert!(settings.notifications),
            other => panic!("expected Status, got {other:?}"),
        }
    }

    // A partial `{}` settings object fills `notifications` from the
    // hand-written default (true), NOT from serde's per-field bool zero —
    // this is what the container-level #[serde(default)] buys.
    #[test]
    fn partial_settings_object_fills_from_default() {
        let s: Settings = serde_json::from_str("{}").unwrap();
        assert!(s.notifications);
        // An explicit value is still honoured.
        let s: Settings = serde_json::from_str(r#"{"notifications":false}"#).unwrap();
        assert!(!s.notifications);
    }

    // The instant-breaks default is load-bearing in the same way notifications
    // is: a #[derive(Default)] would give `false` and silently turn the
    // feature off for every upgrading user.
    #[test]
    fn settings_default_has_instant_breaks_on() {
        assert!(Settings::default().instant_breaks);
    }

    // Upgrade compat: a 0.3.0 state whose `settings` object predates
    // `instant_breaks` (it has only `notifications`) must load with
    // `instant_breaks == true`, filled from the hand-written default via the
    // container-level #[serde(default)] — NOT the bool zero (false).
    #[test]
    fn old_settings_without_instant_breaks_defaults_on() {
        let old = r#"{
            "next_id": 1,
            "blocks": [],
            "active": [],
            "settings": { "notifications": true }
        }"#;
        let st: State = serde_json::from_str(old).unwrap();
        assert!(
            st.settings.instant_breaks,
            "a settings object missing instant_breaks must fill it from the default (ON)"
        );
        assert!(st.settings.notifications, "notifications is still honoured");
        // And a bare Settings object missing the field does the same.
        let s: Settings = serde_json::from_str(r#"{"notifications":true}"#).unwrap();
        assert!(s.instant_breaks);
    }

    // Pin the SetSettings wire tag under the "method" discriminant.
    #[test]
    fn set_settings_wire_tag_round_trips() {
        let req: Request =
            serde_json::from_str(r#"{"method":"set_settings","settings":{"notifications":false}}"#)
                .unwrap();
        assert!(matches!(
            req,
            Request::SetSettings {
                settings: Settings {
                    notifications: false,
                    // Omitted on the wire, so it fills from the default (ON).
                    instant_breaks: true,
                }
            }
        ));
        let json = serde_json::to_string(&Request::SetSettings {
            settings: Settings {
                notifications: true,
                instant_breaks: true,
            },
        })
        .unwrap();
        assert!(json.contains(r#""method":"set_settings""#), "got {json}");
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

    // Pin LockMode's snake_case wire values. `Unlocked` is deliberately
    // pinned to `"normal"`: the variant was renamed, the wire value was not,
    // because released daemons cannot parse an unknown variant.
    #[test]
    fn lock_mode_serializes_snake_case() {
        for (mode, wire) in [
            (LockMode::Unlocked, r#""normal""#),
            (LockMode::PasswordBreaks, r#""password_breaks""#),
            (LockMode::ChallengeBreaks, r#""challenge_breaks""#),
        ] {
            assert_eq!(serde_json::to_string(&mode).unwrap(), wire);
            assert_eq!(serde_json::from_str::<LockMode>(wire).unwrap(), mode);
        }
    }

    // Old state.json compat: Block and ActiveBlock records written before
    // `lock` existed default to Unlocked.
    #[test]
    fn block_and_active_block_without_lock_default_to_unlocked() {
        let block_json = r#"{
            "id": 1,
            "name": "reddit",
            "domains": ["reddit.com"],
            "apps": [],
            "allowance_secs_per_day": 600
        }"#;
        let b: Block = serde_json::from_str(block_json).unwrap();
        assert_eq!(b.lock, LockMode::Unlocked);

        let active_json = format!(
            r#"{{
                "block": {block_json},
                "started_at_unix": 100,
                "ends_at_unix": 200
            }}"#
        );
        let a: ActiveBlock = serde_json::from_str(&active_json).unwrap();
        assert_eq!(a.lock, LockMode::Unlocked);
    }

    // ── allowance policy ────────────────────────────────────────────────────

    // Pin every policy's wire shape: internally tagged on "kind", snake_case,
    // with Disabled deliberately carrying "none".
    #[test]
    fn allowance_policy_wire_round_trips() {
        for (policy, wire) in [
            (AllowancePolicy::Disabled, r#"{"kind":"none"}"#),
            (
                AllowancePolicy::PerDay { secs: 600 },
                r#"{"kind":"per_day","secs":600}"#,
            ),
            (
                AllowancePolicy::RollingWindow {
                    secs: 300,
                    window_secs: 3600,
                },
                r#"{"kind":"rolling_window","secs":300,"window_secs":3600}"#,
            ),
            (
                AllowancePolicy::PerBreak { secs: 300 },
                r#"{"kind":"per_break","secs":300}"#,
            ),
        ] {
            assert_eq!(serde_json::to_string(&policy).unwrap(), wire);
            assert_eq!(
                serde_json::from_str::<AllowancePolicy>(wire).unwrap(),
                policy
            );
        }
    }

    #[test]
    fn allowance_policy_defaults_to_disabled() {
        assert_eq!(AllowancePolicy::default(), AllowancePolicy::Disabled);
    }

    // THE forward-compatibility test. A policy kind written by a newer daemon
    // must not fail the Block (and therefore the whole State) — it degrades to
    // None and the block falls back to its legacy mirror, which is never
    // looser than the real policy.
    #[test]
    fn unknown_policy_kind_degrades_to_legacy_mirror() {
        let json = r#"{
            "id": 1,
            "name": "reddit",
            "domains": [],
            "apps": [],
            "allowance_secs_per_day": 600,
            "allowance": {"kind":"future_thing","x":1}
        }"#;
        let b: Block = serde_json::from_str(json).expect("unknown kind must not fail the Block");
        assert_eq!(b.allowance, None);
        assert_eq!(b.policy(), AllowancePolicy::PerDay { secs: 600 });

        // And with a zero mirror it reads as "no breaks", never as unlimited.
        let json = r#"{
            "id": 1, "name": "reddit", "domains": [], "apps": [],
            "allowance_secs_per_day": 0,
            "allowance": {"kind":"future_thing","x":1}
        }"#;
        let b: Block = serde_json::from_str(json).unwrap();
        assert_eq!(b.policy(), AllowancePolicy::Disabled);
    }

    #[test]
    fn legacy_scalar_folds_into_per_day_or_disabled() {
        let b = Block {
            allowance_secs_per_day: 600,
            ..Default::default()
        };
        assert_eq!(b.policy(), AllowancePolicy::PerDay { secs: 600 });

        let b = Block {
            allowance_secs_per_day: 0,
            ..Default::default()
        };
        assert_eq!(b.policy(), AllowancePolicy::Disabled);
    }

    // An explicit policy is authoritative even when the mirror disagrees —
    // the mirror exists for OLD daemons, never for this one.
    #[test]
    fn explicit_policy_wins_over_disagreeing_mirror() {
        let b = Block {
            allowance_secs_per_day: 600,
            allowance: Some(AllowancePolicy::Disabled),
            ..Default::default()
        };
        assert_eq!(b.policy(), AllowancePolicy::Disabled);

        let b = Block {
            allowance_secs_per_day: 0,
            allowance: Some(AllowancePolicy::PerBreak { secs: 300 }),
            ..Default::default()
        };
        assert_eq!(b.policy(), AllowancePolicy::PerBreak { secs: 300 });
    }

    #[test]
    fn set_policy_refreshes_the_downgrade_mirror() {
        for (policy, mirror) in [
            (AllowancePolicy::Disabled, 0),
            (AllowancePolicy::PerDay { secs: 600 }, 600),
            (
                // The per-WINDOW budget is mirrored, so an old daemon enforces
                // it per day: strictly stricter, deliberately.
                AllowancePolicy::RollingWindow {
                    secs: 300,
                    window_secs: 3600,
                },
                300,
            ),
            (AllowancePolicy::PerBreak { secs: 300 }, 300),
        ] {
            let mut b = Block {
                allowance_secs_per_day: 9999,
                ..Default::default()
            };
            b.set_policy(policy.clone());
            assert_eq!(b.allowance_secs_per_day, mirror, "mirror for {policy:?}");
            assert_eq!(b.policy(), policy);
        }
    }

    // Old state.json compat: a Block written before `allowance` existed loads
    // and resolves through the legacy scalar.
    #[test]
    fn block_without_allowance_field_still_deserializes() {
        let json = r#"{
            "id": 1,
            "name": "reddit",
            "domains": ["reddit.com"],
            "apps": [],
            "allowance_secs_per_day": 600
        }"#;
        let b: Block = serde_json::from_str(json).unwrap();
        assert_eq!(b.allowance, None);
        assert_eq!(b.policy(), AllowancePolicy::PerDay { secs: 600 });
    }

    // ── break history ───────────────────────────────────────────────────────

    fn brk(block_id: u64, start_unix: u64, secs: u64, day: i64) -> BreakRecord {
        BreakRecord {
            block_id,
            start_unix,
            secs,
            day,
        }
    }

    #[test]
    fn absorb_legacy_allowance_preserves_day_and_drains() {
        let mut st = State {
            allowance: vec![
                AllowanceLedger {
                    block_id: 1,
                    day: 42,
                    used_secs: 300,
                },
                AllowanceLedger {
                    block_id: 2,
                    day: 41,
                    used_secs: 60,
                },
            ],
            ..Default::default()
        };
        st.absorb_legacy_allowance();

        assert!(st.allowance.is_empty(), "ledger drained");
        assert_eq!(st.breaks.len(), 2);
        assert_eq!(st.breaks[0], brk(1, 0, 300, 42));
        assert_eq!(st.breaks[1], brk(2, 0, 60, 41));

        // Idempotent — a second absorb adds nothing.
        st.absorb_legacy_allowance();
        assert_eq!(st.breaks.len(), 2);
    }

    #[test]
    fn prune_breaks_keeps_today_and_in_window_rows() {
        let now = 100_000u64;
        let window = 3600u64;
        let mut breaks = vec![
            // Today, but far older than the window: kept for per-day policies.
            brk(1, now - 50_000, 60, 42),
            // Yesterday, but still inside the window: kept for rolling ones.
            brk(1, now - 60, 60, 41),
            // Neither: dropped.
            brk(1, now - 50_000, 60, 41),
        ];
        let out = prune_breaks(&mut breaks, now, 42, window);
        assert_eq!(breaks.len(), 2);
        assert_eq!(breaks[0].day, 42);
        assert_eq!(breaks[1].start_unix, now - 60);
        // Window pruning only — nothing was evicted by the cap.
        assert_eq!(out.window_dropped, 1);
        assert!(out.cap_evicted.is_empty());
        assert!(out.removed_any());
    }

    #[test]
    fn prune_breaks_drops_oldest_at_the_cap() {
        let now = 1_000_000u64;
        let mut breaks: Vec<BreakRecord> = (0..BREAKS_CAP as u64 + 10)
            .map(|i| brk(1, now - 100 + i, 1, 42))
            .collect();
        let out = prune_breaks(&mut breaks, now, 42, MAX_ALLOWANCE_WINDOW_SECS);
        assert_eq!(breaks.len(), BREAKS_CAP);
        // The ten oldest went; the front is now the eleventh record.
        assert_eq!(breaks[0].start_unix, now - 100 + 10);
        // And the cap half of the pass is reported, attributed to its block.
        assert_eq!(out.window_dropped, 0);
        assert_eq!(out.cap_evicted, vec![(1, 10)]);
        assert_eq!(out.cap_evicted_total(), 10);
    }

    /// The reviewer's trigger, verbatim: a `PerBreak` block never depletes, so
    /// a scripted client can loop 1-second breaks against it forever. Under a
    /// GLOBAL cap those rows evicted a second block's exhausted `PerDay`
    /// history and that block silently got its 900s back. Blockwise, block 2
    /// is untouched and stays at `remaining 0`.
    #[test]
    fn cap_eviction_is_per_block_and_cannot_free_another_blocks_budget() {
        let now = 1_000_000u64;
        let today = 42i64;

        let mut breaks = vec![
            // Block 2 spends its whole per-day budget, first and therefore
            // oldest — exactly the position a global drop-oldest reaches.
            brk(2, now - 5_000, 900, today),
        ];
        // Block 1 then floods history well past the cap.
        breaks.extend((0..BREAKS_CAP as u64 + 100).map(|i| brk(1, now - 3_000 + i, 1, today)));

        let out = prune_breaks(&mut breaks, now, today, MAX_ALLOWANCE_WINDOW_SECS);

        // Only block 1 was evicted, and only down to the cap.
        assert_eq!(out.cap_evicted, vec![(1, 100)]);
        assert_eq!(out.window_dropped, 0);

        // Block 2's record survived, so its budget is still spent.
        let view = evaluate_allowance(
            &AllowancePolicy::PerDay { secs: 900 },
            &breaks,
            2,
            now,
            today,
        );
        assert_eq!(view.remaining_secs, 0);
        assert_eq!(breaks.iter().filter(|r| r.block_id == 2).count(), 1);
        assert_eq!(
            breaks.iter().filter(|r| r.block_id == 1).count(),
            BREAKS_CAP
        );
    }

    /// The reviewer's second trigger: a block spends 900s under
    /// `PerDay { 900 }`, is then edited to `RollingWindow { 300, 3600 }` and
    /// restarts inside the hour. The 900s record is in the new window, so the
    /// unclamped `next_free_secs` claimed 15 minutes would return against a
    /// 5-minute budget.
    #[test]
    fn rolling_next_free_secs_cannot_exceed_what_the_policy_withholds() {
        let now = 10_000u64;
        let today = 42i64;
        let breaks = vec![brk(1, now, 900, today)];

        let view = evaluate_allowance(
            &AllowancePolicy::RollingWindow {
                secs: 300,
                window_secs: 3600,
            },
            &breaks,
            1,
            now,
            today,
        );
        assert_eq!(view.budget_secs, 300);
        assert_eq!(view.remaining_secs, 0);
        assert_eq!(view.next_free_unix, Some(now + 3600));
        // Clamped to `budget - remaining`: the whole budget returns, no more.
        assert_eq!(view.next_free_secs, 300);
        assert!(view.next_free_secs <= view.budget_secs);

        // The ordinary case is clamped by CONSUMPTION, not by the budget:
        // 100s spent of 300s can only ever hand back 100s.
        let breaks = vec![brk(1, now, 100, today)];
        let view = evaluate_allowance(
            &AllowancePolicy::RollingWindow {
                secs: 300,
                window_secs: 3600,
            },
            &breaks,
            1,
            now,
            today,
        );
        assert_eq!(view.remaining_secs, 200);
        assert_eq!(view.next_free_secs, 100);
    }

    // Old state.json compat: state carrying only legacy allowance rows and no
    // `breaks` field still loads, with the ledger intact for absorption.
    #[test]
    fn state_with_only_legacy_allowance_still_deserializes() {
        let old = r#"{
            "next_id": 1,
            "blocks": [],
            "allowance": [{"block_id": 1, "day": 42, "used_secs": 300}]
        }"#;
        let mut st: State = serde_json::from_str(old).unwrap();
        assert!(st.breaks.is_empty());
        assert_eq!(st.allowance.len(), 1);
        st.absorb_legacy_allowance();
        assert_eq!(st.breaks, vec![brk(1, 0, 300, 42)]);
    }

    // ── allowance reducers ──────────────────────────────────────────────────

    const HOUR: u64 = 3600;

    fn rolling(secs: u64, window_secs: u64) -> AllowancePolicy {
        AllowancePolicy::RollingWindow { secs, window_secs }
    }

    #[test]
    fn evaluate_disabled_is_all_zero() {
        let v = evaluate_allowance(&AllowancePolicy::Disabled, &[], 1, 1000, 42);
        assert_eq!(v, AllowanceView::default());
        assert_eq!(v.next_free_unix, None);
    }

    #[test]
    fn evaluate_per_day_sums_todays_rows_for_this_block() {
        let breaks = vec![
            brk(1, 1000, 120, 42),
            brk(1, 2000, 60, 42),
            brk(1, 500, 999, 41),  // yesterday
            brk(2, 1000, 999, 42), // another block
        ];
        let v = evaluate_allowance(&AllowancePolicy::PerDay { secs: 600 }, &breaks, 1, 5000, 42);
        assert_eq!(v.budget_secs, 600);
        assert_eq!(v.remaining_secs, 420);
        assert_eq!(v.next_free_unix, None);
        assert_eq!(v.next_free_secs, 0);
    }

    #[test]
    fn evaluate_per_day_saturates_when_overspent() {
        let breaks = vec![brk(1, 1000, 900, 42)];
        let v = evaluate_allowance(&AllowancePolicy::PerDay { secs: 600 }, &breaks, 1, 5000, 42);
        assert_eq!(v.remaining_secs, 0);
    }

    // PerBreak never reduces: ten recorded breaks change nothing.
    #[test]
    fn evaluate_per_break_ignores_history() {
        let policy = AllowancePolicy::PerBreak { secs: 300 };
        let empty = evaluate_allowance(&policy, &[], 1, 1000, 42);
        let breaks: Vec<BreakRecord> = (0..10).map(|i| brk(1, 1000 + i * 60, 300, 42)).collect();
        let after = evaluate_allowance(&policy, &breaks, 1, 10_000, 42);
        assert_eq!(empty, after);
        assert_eq!(after.budget_secs, 300);
        assert_eq!(after.remaining_secs, 300);
        assert_eq!(after.next_free_unix, None);
    }

    // The window boundary is strict: a record at exactly `now - window` has
    // left, one a second later has not.
    #[test]
    fn evaluate_rolling_boundary_is_exclusive() {
        let now = 100_000u64;
        let at_boundary = vec![brk(1, now - HOUR, 300, 42)];
        let v = evaluate_allowance(&rolling(300, HOUR), &at_boundary, 1, now, 42);
        assert_eq!(v.remaining_secs, 300, "boundary record has left the window");
        assert_eq!(v.next_free_unix, None);

        let just_inside = vec![brk(1, now - HOUR + 1, 300, 42)];
        let v = evaluate_allowance(&rolling(300, HOUR), &just_inside, 1, now, 42);
        assert_eq!(v.remaining_secs, 0);
        assert_eq!(v.next_free_unix, Some(now + 1));
        assert_eq!(v.next_free_secs, 300);
    }

    #[test]
    fn evaluate_rolling_next_free_sums_ties() {
        let now = 100_000u64;
        let breaks = vec![
            brk(1, now - 1800, 60, 42),
            brk(1, now - 1800, 90, 42), // same instant: ties sum
            brk(1, now - 600, 30, 42),  // later, so not the next to free
        ];
        let v = evaluate_allowance(&rolling(300, HOUR), &breaks, 1, now, 42);
        assert_eq!(v.remaining_secs, 300 - 180);
        assert_eq!(v.next_free_unix, Some(now - 1800 + HOUR));
        assert_eq!(v.next_free_secs, 150);
    }

    // A folded legacy ledger row (`start_unix == 0`) must never count against
    // a window it carries no timing for — but it still counts for the day.
    #[test]
    fn evaluate_legacy_zero_start_counts_per_day_only() {
        let breaks = vec![brk(1, 0, 300, 42)];
        let v = evaluate_allowance(&rolling(300, HOUR), &breaks, 1, 100_000, 42);
        assert_eq!(v.remaining_secs, 300, "never counts against a window");
        assert_eq!(v.next_free_unix, None);

        let v = evaluate_allowance(
            &AllowancePolicy::PerDay { secs: 600 },
            &breaks,
            1,
            100_000,
            42,
        );
        assert_eq!(v.remaining_secs, 300, "but does count for the day");
    }

    // Over a FIXED history, used can only fall as now advances — records age
    // out of the window and never back into it.
    #[test]
    fn evaluate_rolling_usage_is_monotone_in_now() {
        let base = 100_000u64;
        let breaks = vec![
            brk(1, base, 60, 42),
            brk(1, base + 600, 60, 42),
            brk(1, base + 1200, 60, 42),
        ];
        let policy = rolling(600, HOUR);
        // Start at the newest record, so every later `now` only ages rows out.
        let start = base + 1200;
        let mut last_used = u64::MAX;
        for step in 0..40u64 {
            let v = evaluate_allowance(&policy, &breaks, 1, start + step * 120, 42);
            let used = v.budget_secs - v.remaining_secs;
            assert!(
                used <= last_used,
                "used rose at step {step}: {last_used} -> {used}"
            );
            last_used = used;
        }
        assert_eq!(last_used, 0, "everything eventually ages out");
    }

    // A clock rolled back before the window length must saturate, not
    // underflow into a horizon that counts nothing.
    #[test]
    fn evaluate_rolling_survives_a_clock_rollback() {
        let breaks = vec![brk(1, 10, 300, 42)];
        let v = evaluate_allowance(&rolling(300, HOUR), &breaks, 1, 100, 42);
        assert_eq!(v.remaining_secs, 0, "rollback must not free allowance");
        assert_eq!(v.next_free_unix, Some(10 + HOUR));
    }

    // ── compute_grant (ported from the daemon, against the new signature) ────

    #[test]
    fn grant_errors_without_allowance() {
        assert_eq!(
            compute_grant(&AllowancePolicy::Disabled, &[], 1, 2000, 1000, 42, 60),
            Err("this block has no break allowance")
        );
    }

    #[test]
    fn grant_errors_when_exhausted_per_day() {
        let policy = AllowancePolicy::PerDay { secs: 600 };
        let breaks = vec![brk(1, 100, 600, 42)];
        assert_eq!(
            compute_grant(&policy, &breaks, 1, 2000, 1000, 42, 60),
            Err("no break allowance left today")
        );
        // Saturating: spent beyond the budget still reads as exhausted.
        let breaks = vec![brk(1, 100, 700, 42)];
        assert_eq!(
            compute_grant(&policy, &breaks, 1, 2000, 1000, 42, 60),
            Err("no break allowance left today")
        );
    }

    // The rolling exhaustion message is its own string, and deliberately
    // carries no wall-clock time.
    #[test]
    fn grant_errors_when_exhausted_in_window() {
        let breaks = vec![brk(1, 900, 300, 42)];
        assert_eq!(
            compute_grant(&rolling(300, HOUR), &breaks, 1, 5000, 1000, 42, 60),
            Err("no break allowance left in the current window")
        );
    }

    #[test]
    fn grant_errors_when_block_ended() {
        let policy = AllowancePolicy::PerDay { secs: 600 };
        assert_eq!(
            compute_grant(&policy, &[], 1, 1000, 1000, 42, 60),
            Err("this block has already ended")
        );
        assert_eq!(
            compute_grant(&policy, &[], 1, 999, 1000, 42, 60),
            Err("this block has already ended")
        );
        // Same on the other kinds.
        assert_eq!(
            compute_grant(&rolling(300, HOUR), &[], 1, 999, 1000, 42, 60),
            Err("this block has already ended")
        );
        assert_eq!(
            compute_grant(
                &AllowancePolicy::PerBreak { secs: 300 },
                &[],
                1,
                999,
                1000,
                42,
                60
            ),
            Err("this block has already ended")
        );
    }

    #[test]
    fn grant_errors_on_zero_request() {
        for policy in [
            AllowancePolicy::PerDay { secs: 600 },
            rolling(300, HOUR),
            AllowancePolicy::PerBreak { secs: 300 },
        ] {
            assert_eq!(
                compute_grant(&policy, &[], 1, 2000, 1000, 42, 0),
                Err("break length must be at least 1 second"),
                "for {policy:?}"
            );
        }
    }

    #[test]
    fn grant_capped_by_remaining_allowance() {
        // remaining = 600 - 590 = 10; block time is ample.
        let breaks = vec![brk(1, 100, 590, 42)];
        assert_eq!(
            compute_grant(
                &AllowancePolicy::PerDay { secs: 600 },
                &breaks,
                1,
                1_000_000,
                1000,
                42,
                100
            ),
            Ok(10)
        );
        // Same cap through the window arm.
        let breaks = vec![brk(1, 900, 290, 42)];
        assert_eq!(
            compute_grant(&rolling(300, HOUR), &breaks, 1, 1_000_000, 1000, 42, 100),
            Ok(10)
        );
    }

    #[test]
    fn grant_capped_by_remaining_block_time() {
        // block ends in 5s; allowance is ample.
        assert_eq!(
            compute_grant(
                &AllowancePolicy::PerDay { secs: 600 },
                &[],
                1,
                1005,
                1000,
                42,
                100
            ),
            Ok(5)
        );
    }

    #[test]
    fn grant_uses_request_when_smallest() {
        assert_eq!(
            compute_grant(
                &AllowancePolicy::PerDay { secs: 600 },
                &[],
                1,
                1_000_000,
                1000,
                42,
                30
            ),
            Ok(30)
        );
    }

    // PerBreak grants the same amount however much history there is.
    #[test]
    fn grant_per_break_is_unaffected_by_history() {
        let policy = AllowancePolicy::PerBreak { secs: 300 };
        let breaks: Vec<BreakRecord> = (0..10).map(|i| brk(1, 1000 + i, 300, 42)).collect();
        assert_eq!(
            compute_grant(&policy, &breaks, 1, 1_000_000, 5000, 42, 300),
            Ok(300)
        );
    }

    // ── validate_policy ─────────────────────────────────────────────────────

    #[test]
    fn validate_policy_accepts_sane_policies() {
        for p in [
            AllowancePolicy::Disabled,
            AllowancePolicy::PerDay { secs: 1 },
            AllowancePolicy::PerDay { secs: 24 * 3600 },
            AllowancePolicy::PerBreak { secs: 300 },
            rolling(1, 60),
            rolling(300, HOUR),
            rolling(MAX_ALLOWANCE_WINDOW_SECS, MAX_ALLOWANCE_WINDOW_SECS),
        ] {
            assert_eq!(validate_policy(&p), None, "should accept {p:?}");
        }
    }

    #[test]
    fn validate_policy_rejects_zero_budgets() {
        for p in [
            AllowancePolicy::PerDay { secs: 0 },
            AllowancePolicy::PerBreak { secs: 0 },
            rolling(0, HOUR),
        ] {
            let msg = validate_policy(&p).unwrap_or_else(|| panic!("should reject {p:?}"));
            assert!(msg.contains("no breaks"), "steer to \"no breaks\": {msg}");
        }
    }

    #[test]
    fn validate_policy_rejects_out_of_range_budgets_and_windows() {
        assert_eq!(
            validate_policy(&AllowancePolicy::PerDay {
                secs: 24 * 3600 + 1
            }),
            Some("break allowance cannot exceed 24 hours")
        );
        assert_eq!(
            validate_policy(&AllowancePolicy::PerBreak {
                secs: 24 * 3600 + 1
            }),
            Some("break allowance cannot exceed 24 hours")
        );
        assert_eq!(
            validate_policy(&rolling(30, 59)),
            Some("break window must be between 1 minute and 24 hours")
        );
        assert_eq!(
            validate_policy(&rolling(30, MAX_ALLOWANCE_WINDOW_SECS + 1)),
            Some("break window must be between 1 minute and 24 hours")
        );
        // A budget bigger than its own window can never bind.
        assert_eq!(
            validate_policy(&rolling(3601, HOUR)),
            Some("break allowance cannot exceed its own window")
        );
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
            allowance: vec![],
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
            settings: Settings::default(),
            instant_breaks_degraded: false,
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
