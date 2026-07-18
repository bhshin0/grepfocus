# Premium usage stats milestone (B2.b, `premium` branch)

Status: **implemented, reviewed, and live-verified** (2026-07-17).

The second of the three B2 capabilities (`lock_modes` shipped; `pomodoro`
remains). Usage stats give the user a truthful record of their focus habit —
what they blocked, how long they stayed focused, and how often the tool
caught them reaching for a temptation.

## Scope decision (Option A)

Domain blocks are **not observable**: a blocked domain is `0.0.0.0` in
`/etc/hosts`, so the browser fails the connection locally and the daemon never
sees the attempt. Counting per-domain attempts would need a local DNS
resolver/proxy inspecting all lookups — a large, privileged, fragile subsystem
(systemd-resolved / NetworkManager / VPN / container interactions) and
philosophically wrong for an akrasia-only tool where root bypass is already out
of scope. The nft DoH-drop counter was also rejected: it counts DoH/DoT
keepalive packets, not domain visits, so any number it shows misleads.

So this milestone ships only what is **honestly measurable**, and reframes
"blocked attempts" into the stat that actually motivates a focus tool —
**temptation events the tool caught**:

- **Focus history** — every block run: name, start, end, duration, and whether
  it was manual or scheduled.
- **App-block events** — distinct processes SIGKILLed by procwatch, deduped by
  PID and attributed to the block that matched. ("GrepFocus closed Steam 6× this
  week.")
- **Break activity** — breaks taken (count + total seconds) and, importantly,
  **refused break attempts** (wrong challenge / password-locked with no unlock),
  a strong akrasia signal.
- **Streaks** — consecutive days with at least one completed focus block,
  derived (not stored).

Companion change: reword the store's "Usage stats" row (grepfocus-web
`lib/features.ts`) away from "Blocked-attempt counts" — it stays `comingSoon`
until this ships.

## Data model

A new `UsageStats` on `State` (integrity-protected by the existing HMAC state
file — no second file, no new migration surface). `#[serde(default)]` so old
state loads clean.

```
State.stats: UsageStats {
    /// Capped ring of completed focus sessions, newest last. Cap ~200.
    sessions: Vec<FocusSession> {
        block_id, name, started_at_unix, ended_at_unix,
        origin: Manual | Schedule, duration_secs (derived on record),
    },
    /// Per-local-day rollups, retained ~365 days. The streak + chart source.
    days: Vec<DayStat> {
        day: i64,            // num_days_from_ce, same unit as allowance ledger
        focus_secs: u64,     // summed completed-session duration credited to the day
        sessions_completed: u32,
        breaks_taken: u32,
        break_secs: u64,
        breaks_refused: u32,
        app_kills: u32,
    },
    /// Lifetime totals (cheap running counters, never pruned).
    totals: LifetimeTotals { focus_secs, sessions, app_kills, breaks_refused },
}
```

Retention is enforced on every record: `sessions` truncated to the cap
(drop oldest), `days` retained to the window. Bounded by construction — the
stats blob can never grow without limit.

## Recording hooks (all daemon-side; the GUI never writes stats)

1. **Session start** — already captured: `ActiveBlock.started_at_unix` is set
   at both activation sites (`StartBlock` arm, scheduler reconcile step 3). No
   new write; the session row is emitted at *end*.
2. **Session end — the single choke point is scheduler `reconcile`.** Manual
   blocks can't be cancelled (only wall-clock expiry, step 1); scheduled blocks
   end via step 1 or step 2. Both are `retain` drops. Change those two `retain`
   calls to *partition*, and for each dropped `ActiveBlock` push a
   `FocusSession` and credit `DayStat`/`totals`. This runs under the state lock,
   in the same tick that already sets `changed = true` and saves — zero extra
   fsyncs. A daemon restart mid-block does **not** emit a false end (the
   `ActiveBlock` persists in `State` and is still active on reload).
3. **Break taken** — `TakeBreak` arm, right where `record_break` + `info!("break
   started")` already run (ipc.rs ~388), inside the same save. Increment
   `breaks_taken` + `break_secs` for today.
4. **Break refused** — `TakeBreak` arm, at the `break_gate` rejection
   (ipc.rs ~358) *before* the early `return err(msg)`. Increment
   `breaks_refused`. NB: this needs the refusal path to record-and-save before
   returning; keep it cheap and never let a stats-save failure convert a
   correct refusal into a 500 — log and drop the increment if save fails.
5. **App kills** — `procwatch::sweep`. Two problems to solve:
   - *Attribution*: `sweep` currently gets a flat `Vec<AppMatcher>`. Thread
     `(block_id, matchers)` groups through `enforced_matchers`/`sweep` so a kill
     can be credited to a block. (Aggregate `app_kills` is the shipped number;
     per-block breakdown is optional polish — keep the day/total counters
     aggregate to avoid bloat.)
   - *Dedup + disk churn*: the 500 ms sweep must not count the same PID every
     tick nor fsync per kill. Keep an in-memory `recently_killed: HashSet<pid>`
     with a short TTL (or cleared when the pid disappears) so each PID counts
     once, and accumulate kills in an in-memory counter on `Daemon`
     (`app_kills_pending: AtomicU64` or a `Mutex<u32>`). Fold the pending count
     into today's `DayStat` opportunistically at the next state save from any
     cause — exactly the `high_water_unix` "accumulate in memory, persist when
     something else saves" pattern. Accepted trade-off: a crash loses at most
     the unflushed kill count.

## Read path + gating

- New `GetUsageStats {}` IPC → `Response::UsageStats { ... }`. **Gated on the
  `usage_stats` feature** (the read, not the recording): recording is always on
  and harmless, so a user who buys later sees their prior history. Unlicensed
  → return the feature message (GUI hides the tab). This is the only gate;
  stats are not enforcement, so none of the activation-snapshot machinery
  applies.
- **Streaks are computed in the read path** from `days`: the run of consecutive
  days (ending today or yesterday — today may be mid-progress) with
  `sessions_completed > 0`. Never stored (a stored streak would rot across a
  restart or a date change).
- Response carries: lifetime totals, the last N sessions, the day rollups for a
  charting window (e.g. 30 days), current + longest streak.

## GUI

A **Stats** tab (shown only when `usage_stats` is licensed, mirroring the
license-tab pattern; the daemon stays the authority and still returns the
feature message if asked unlicensed):
- headline tiles: current streak, total focus time, sessions completed, apps
  blocked, temptations resisted (refused breaks);
- a simple per-day focus bar for the last ~30 days (inline, no chart lib —
  keep the bundle dependency-free);
- a recent-sessions list (name, when, duration, manual/scheduled).

## Testing

- Pure rollup/credit helpers (`credit_session`, `credit_break`, retention
  truncation, streak computation) unit-tested with no clock/IO — same
  discipline as `break_gate`/`reconcile`.
- `reconcile` partition-and-record: a dropped active emits exactly one session
  and credits the day; a persisted mid-block active on reload emits none.
- procwatch PID dedup: same pid across ticks counts once; a new pid counts
  again.
- `GetUsageStats` gating: unlicensed → feature message; licensed → payload.
- Streak edge cases: today-only, gap breaks the streak, empty history.

## Open choices baked in (revisit if wrong)

- **Stats live in `State`, not a separate file** — integrity-protected, one
  save path. Cost: the hot state file carries the stats blob; acceptable
  because it's bounded and session/break writes are infrequent, and app-kills
  never write directly.
- **Record always, gate the read** — simplest and most generous; free-tier
  recording is cheap and lets a later purchase reveal history.
- **Aggregate app-kill counters** (not per-domain, not per-app persisted) — the
  honest, bounded number. Per-block attribution is available in `sweep` if we
  later want a breakdown.

## What shipped (all commits gated on ./scripts/check.sh)

- `54dc41d` premium: core + daemon. `UsageStats`/`FocusSession`/`DayStat`/
  `LifetimeTotals`/`Origin` in core with pure, unit-tested helpers
  (`credit_session`/`credit_break`/`credit_break_refused`/`credit_app_kills`/
  `compute_streak`, retention + ring cap); `stats` on `State`; recording in
  scheduler reconcile (partition-and-record on the two block-drop points),
  `TakeBreak` (taken + refused-defensively), procwatch (per-block attribution,
  PID dedup, in-memory counter folded into today's rollup on the next save);
  `GetUsageStats` IPC gated on `usage_stats`; streak computed on read. 19 tests.
- `1e0b733` gui: the Stats tab — `get_usage_stats` command (registered at all
  three ACL sites), shown only when licensed (daemon stays the gate), headline
  tiles, a dependency-free 30-day focus-bar strip, and a newest-first recent
  sessions list.
- Companion: grepfocus-web `e89fa9a` reworded the "Usage stats" store row away
  from "Blocked-attempt counts" (domain attempts aren't measured).

## Live verification (Fedora 44, 2026-07-17, daily driver)

| Check | Result |
|---|---|
| `get_usage_stats` served by the deployed daemon; licensed → payload | PASS |
| Manual block run to expiry records exactly one `FocusSession` (name/duration/origin) | PASS |
| `focus_secs` + `sessions_completed` + today's `DayStat` credited | PASS |
| Refused break (wrong challenge) increments `breaks_refused` (day + total) and still refuses | PASS |
| Taken break increments `breaks_taken` + `break_secs` | PASS |
| App kills counted per distinct PID, deduped across 500 ms ticks (2 spawns → 2, not N) | PASS |
| Streak computes to 1 for a single completed day | PASS |
| **Daemon restart**: all stats persist (read back off disk) | PASS |
| **Daemon restart**: a still-running block records NO false "ended" session | PASS |
| GUI Stats tab hidden without a license, shown with the trial | PASS |

## Not in this milestone

`pomodoro` (B2.c). Per-domain attempt counting (rejected above). Per-app
persisted breakdowns, CSV/export, and any cross-device sync (stateless offline
model by design).
