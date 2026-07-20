# Allowance policies + nested schedules milestone (`allowance-policies`)

Status: **implemented and reviewed; live verification pending** (2026-07-19).

Two changes to how breaks are configured, plus a startup-safety fix that turned
out to gate both, plus a naming cleanup that makes the two break axes legible.

## The two axes

Breaks have two independent axes. Both are meant to grow, and future ideas must
land on the right one:

- **Allowance** — *how much* break time. `AllowancePolicy` + `compute_grant`.
  Either/or by construction; policies never stack. **Free.**
- **Lock** — *is taking a break locked, and how do you unlock it?* `LockMode` +
  `lock_gate`. `Unlocked` means no lock; every other variant locks breaks and
  names the way out. **Premium** (`LOCK_MODES`), enforced when the block is
  SAVED, not when it runs.

They compose. A block is *(allowance, lock)*:

| want | lock | allowance |
|---|---|---|
| 5 min per hour | `Unlocked` | `RollingWindow { 300, 3600 }` |
| type a string → 5 min | `ChallengeBreaks` | `PerBreak { 300 }` |
| password → 5 min | `PasswordBreaks` | `PerBreak { 300 }` |
| can't break for the first hour | `TimeLock { secs }` *(future)* | any |

**Friction is a lock; duration is an allowance.** Putting password or countdown
friction into `AllowancePolicy` would duplicate `ChallengeBreaks` and leave two
competing lock mechanisms — do not do it.

## Scope decision: rolling window, not fixed clock slots

Fixed hourly slots don't deliver what "5 min per hour" promises: 5 min at 09:58
plus 5 min at 10:00 is ten consecutive minutes, entirely within the rules. For a
general quota that's a rounding error; for an akrasia tool it is precisely the
failure mode, because the slot boundary is exactly where a motivated user learns
to wait — and a countdown timer would tell them when. So the interval policy is
a **rolling window**: at most `secs` of break within any trailing `window_secs`.

Breaks are bucketed by their **start** time (`used = Σ secs where start_unix >
now - window`). Monotone as the clock advances and slightly conservative, with
one documented exception: a break that started *before* the window opened counts
as zero even if it is still running. That is bounded by the break length and
irrelevant while breaks are shorter than the window.

## Data model

```rust
#[serde(tag = "kind", rename_all = "snake_case")]
enum AllowancePolicy {
    #[serde(rename = "none")] Disabled,
    PerDay { secs },
    RollingWindow { secs, window_secs },
    PerBreak { secs },          // no cumulative cap; the friction is the LOCK
}
```

`Block` gains `allowance: Option<AllowancePolicy>` and **keeps**
`allowance_secs_per_day` as a **downgrade mirror**. `Block::policy()` is the
single reader (explicit policy wins; else the mirror `>0` → `PerDay`; else
`Disabled`); `Block::set_policy()` is the only writer and refreshes both, so
they cannot drift. For a rolling policy the mirror carries the per-window
budget, so an older daemon enforces it per *day* — strictly stricter.

**Forward compatibility is load-bearing, not decorative.** An internally-tagged
enum hard-errors on an unknown tag, and since `eee2316` an authentic-but-
unparseable state file is *fatal at startup*. So `allowance` deserializes
through a lenient helper: an unrecognized policy kind degrades to `None` and the
block falls back to its legacy mirror. Adding a fifth policy kind later
therefore cannot brick an older daemon. Same doctrine as `deserialize_active`.

### Break history replaces the daily counter

```rust
struct BreakRecord { block_id, start_unix, secs, day }
```

`AllowanceLedger` was a counter; history is a strict superset — per-day usage is
the records with `day == today`, rolling usage the records inside the window. So
**every policy is a pure reducer over one history**, and a future policy kind
needs only a new reducer arm.

`day` is **stored, not derived** from `start_unix`: per-day bucketing is
timezone-dependent, and every reducer here stays clock-free (the caller passes
`today` in, as `reconcile` already did). Deriving it would let a DST change
retroactively re-bucket an already-charged break.

`State.breaks` is a new field; `State.allowance` is retained and folded once by
`absorb_legacy_allowance` (each row → one record with `start_unix: 0`, ancient
enough never to count against a window, while its `day` preserves per-day spend
exactly), then always written empty. It could not reuse the same field — old
rows cannot deserialize into `BreakRecord`, and one bad element fails the whole
`State`.

Retention: `prune_breaks` keeps `day == today || start_unix > now - max_window`,
then a `BREAKS_CAP` backstop applied **per block**. The cap's drop-oldest is a
*loosening*, so it is a backstop rather than a policy: it is capped blockwise so
one block's churn cannot evict another's still-relevant spend and silently hand
that block its budget back, and `reconcile` warns with the block ids and counts
whenever it fires. The overall bound is `BREAKS_CAP × distinct blocks` — the
per-block row count grows as fast as a client can call `take_break`, whereas the
number of blocks only grows by deliberate UI action, so the unbounded axis is the
one that is capped. Note the daily **reset**
now lives in the reducer's `day == today` filter rather than in pruning — which
is strictly more robust, since a daemon that missed midnight ticks can no longer
over-credit.

## Read path

`evaluate_allowance` returns an `AllowanceView { budget_secs, remaining_secs,
next_free_unix, next_free_secs }`. `next_free_secs` is required, not redundant:
"3 min available now, 2 more at 10:14" cannot be rendered from an instant alone.

`compute_grant` keeps the pre-existing four-check order so the `PerDay` accept
path is byte-identical, and its exhaustion message varies by policy —
`"no break allowance left today"` (pinned byte-for-byte by existing tests) vs
`"no break allowance left in the current window"`. The rolling message is
deliberately **clock-free**: the GUI formats `next_free_unix` itself, so
`chrono::Local` stays out of a pure helper.

`Response::Status` gains `allowance: Vec<AllowanceStatus>`, computed by the
daemon. Raw history is never shipped to the frontend and window math is never
reimplemented in TypeScript. `allowance_used` is **kept and still emitted**, now
derived — so an old GUI against a new daemon renders identically.

The policy is snapshotted on `ActiveBlock` at all three activation sites, like
`apps_enforced` and `lock`. It was previously snapshotted only *implicitly* via
the embedded block — safe only because `UpdateBlock` refuses while active. Now
that a per-card allowance editor exists, that refusal is under real pressure;
the moment it is relaxed, an implicit policy would let a mid-block edit
retroactively change the budget a running block has already spent against.

## GUI

- A **break-allowance picker** (kind dropdown + conditional minutes/window
  inputs) on the New-block form and on a new **per-card edit form**, sharing
  `readPolicy`/`writePolicy`/`readBlockForm` so the two cannot drift. The edit
  form disables itself for active blocks rather than inviting the daemon's
  refusal.
- `renderActive` branches on the policy kind: `12 min available now · +5 min at
  10:14` for rolling, `12 min left today` for per-day, no counter for per-break.
  Exhaustion is judged in whole minutes, preserving the pre-policy behaviour
  (with 30 s left, a 1-minute request would be refused, so the button stays
  disabled). A fallback to `allowance_used` remains for a new GUI against an old
  daemon.
- **Schedules moved inside the block cards** and the tab is gone. Storage is
  untouched — this is UI-only. One shared `<dialog>` rather than a form per
  card; the block `<select>` is deleted outright, which is the point. The
  `id === 0` add/update sentinel is replaced by an explicit `SchedIntent`. The
  card shows `3 schedules (1 disabled)` beside Delete, because a *disabled*
  schedule still blocks `DeleteBlock` and a bare count would make that refusal
  look wrong.

Schedules remain premium; the disclosure renders for everyone with the hint
inside the dialog, and the daemon's refusal is surfaced verbatim with the dialog
left open so the entered schedule is not lost.

## What shipped (all commits gated on `./scripts/check.sh`)

- `eee2316` **Refuse to start when a verified state.json fails to parse.** A
  pre-existing data-loss bug, found while sizing the risk of adding a tagged
  enum to `Block`. `load_in` swallowed JSON parse failures into the HMAC branch;
  the caller read that as corruption, started from `State::default()`, cleared
  the hosts block, and the next save overwrote `state.json` — losing every
  block, schedule, stat and the licence token. Bad MAC still means start fresh;
  good MAC + unparseable body is now fatal, distinguished by a downcast-detected
  `UnparseableState` rather than by message matching.
- `5f7e7fb` Rename the break-lock axis: `break_gate`→`lock_gate`,
  `LockMode::Normal`→`Unlocked`, and a `LockContext` struct so a future
  `TimeLock` is a field addition rather than churn across 28 call sites. **The
  wire value stays `"normal"`** — `LockMode` serializes as a bare string with no
  unknown-variant fallback, so emitting `"unlocked"` would be unreadable to a
  released 0.2.0 daemon, and unreadable is now fatal.
- `79e7fac` core: `AllowancePolicy`, the lenient deserializer, `Block::policy()`
  / `set_policy()`.
- `5c7240f` core: `BreakRecord`, `State::breaks`, `absorb_legacy_allowance`,
  `prune_breaks`, retention caps.
- `05167de` core: the pure reducers — `evaluate_allowance`, `compute_grant`,
  `validate_policy`.
- `e43e663` daemon: switch the break path onto policies in one commit, so no
  intermediate state has two live ledgers. Load absorbs legacy rows; `TakeBreak`
  uses core's grant and appends history; `reconcile` prunes; `GetStatus` emits
  both the new and the derived-legacy shapes.
- `957d5f9` core+daemon: snapshot the policy on `ActiveBlock` at all three
  activation sites.
- `34cc652` daemon: `validate_policy` + mirror normalization on `AddBlock` /
  `UpdateBlock`. No licence gate — the allowance axis is free.
- `5b8da38` gui: the `update_block` command (all three ACL sync points) and
  `Status.allowance` on `StatusOut`.
- `c54fc69` gui: the policy picker and the per-card block editor.
- `1e6d190` gui: render the break row from the policy, not the daily counter.
- `9e445a4` gui: nest schedules inside block cards and drop the tab.
- `6a4498e` core+daemon: two defects found by an adversarial review of the
  branch. (1) `BREAKS_CAP` evicted oldest-first across *all* blocks, so a
  scripted client looping short breaks on a `PerBreak` block could evict another
  block's exhausted `PerDay` spend and silently restore its whole daily budget —
  the cap is now per-block, and `prune_breaks` returns a `PruneOutcome` so
  `reconcile` can warn when it fires (the plan required this and it had been
  dropped). (2) `next_free_secs` could exceed `budget_secs` after a per-day →
  rolling policy edit, rendering "15 min returns at…" against a 5-minute budget;
  it is now clamped to `budget_secs - remaining_secs`, the amount the policy is
  actually withholding, which is also the correct figure in the ordinary case.

## Live verification (Fedora 44, daily driver)

| # | Check | Result |
|---|---|---|
| 0 | Valid MAC + malformed JSON → daemon refuses to start, file intact | pending |
| 1 | Upgrade over a real `state.json` with today's legacy rows mid-block: same remaining minutes; next save writes `breaks` and empties `allowance` | pending |
| 2 | Pre-upgrade in-flight `ActiveBlock`: break row still works via the embedded-block fallback | pending |
| 3 | Rolling `{300, 600}`: 3 min, then 2 min, third refused with the window message; wait past the window → returns; the "+X min at HH:MM" matches the wall clock | pending |
| 4 | Midnight rollover on `PerDay`: resets; history pruned to the window | pending |
| 5 | Daemon restart mid-window: usage survives (absolute `start_unix`), no free reset | pending |
| 6 | `update_block` refused while active; the card renders the refusal verbatim | pending |
| 7 | Nested schedules: add / edit / enable / delete from a card; the schedule still auto-fires | pending |
| 8 | Free tier: every allowance policy configurable and a rolling break taken — no gate anywhere | pending |
| 9 | Old GUI binary vs new daemon: `allowance_used` still renders | pending |
| 10 | HMAC integrity unchanged: corrupt the MAC and confirm the load still refuses | pending |
| 11 | A pre-existing `PasswordBreaks` block still loads and still locks its breaks (wire value `"normal"` unchanged) | pending |
| 12 | Pomodoro auto-breaks still consume no allowance and record no `BreakRecord` | pending |

## Open choices baked in (revisit if wrong)

- **Legacy mirror kept on disk** rather than dropped — it is the only thing that
  makes a downgrade survivable while there is no version field in `State`.
- **Record always, gate nothing** — the allowance axis is free, so unlike the
  lock axis there is no licence check anywhere on the break path. Moving it to
  premium later would need a feature key, a gate at *save* time beside the
  existing `MSG_LOCK_MODES` one with an `update_needs_*_license` grandfathering
  helper, and still nothing on the break path.
- **`PerBreak` consults no history** — a break is still recorded (stats and the
  derived per-day figure need it) but nothing reduces the next grant.
- **Rolling buckets by start time**, accepting the documented
  started-before-the-window edge, rather than tracking partial overlap.

## Not in this milestone

`LockMode::TimeLock` and any countdown lock (the lock axis is unchanged apart
from the rename). Per-interval pomodoro crediting. Relaxing the
`"cannot edit a block while it is active"` refusal — the `ActiveBlock` snapshot
now makes that *possible*, but it stays refused. Storage-level schedule nesting
(deliberately UI-only). CSV/export and any cross-device sync.
