# Premium pomodoro milestone (B2.c, `premium` branch)

Status: **implemented, reviewed, and live-verified** (2026-07-17).

The last of the three B2 capabilities (`lock_modes` and `usage_stats`
shipped). A pomodoro session drives ONE saved block through alternating
focus/break intervals automatically: enforce during focus, lift during the
short break, cycle, then end. It reuses the existing `ActiveBlock` machinery
rather than inventing a parallel enforcement path.

## Commitment model: HYBRID (interval-locked) — decided 2026-07-17

The defining product choice for an akrasia-only tool. GrepFocus's standing
rule is "active blocks cannot be cancelled." Pomodoro keeps that *within* a
focus interval but relaxes it at the seams:

- A **focus interval cannot be interrupted** — same as any running block. No
  stop mid-focus.
- The session can be **ended only during a break** (`StopPomodoro` is refused
  while phase == Focus).

Rationale: you can't cave in the akratic moment, but you're not trapped for a
rigid multi-hour set if life intervenes. **This must be unmistakable in the
GUI** (explicit per the owner): the rule is stated in plain words on the
Pomodoro screen, and the "End session" button is visibly disabled during focus
(tooltip: "Available during breaks") and enabled during breaks.

## How it drives a block

- New `Originator::Pomodoro` on the `ActiveBlock` that the session enforces
  (mirrors `Manual`/`Schedule`; add the two match arms — reconcile step 2
  retains it like `Manual`, and `Origin::from` maps it to a new
  `Origin::Pomodoro` for stats labelling).
- Auto-breaks reuse **`ActiveBlock.break_until_unix`** — the exact field the
  scheduler already uses to lift enforcement and resume. Pomodoro sets it
  DIRECTLY (not via `TakeBreak`), so it does **not** touch the break-allowance
  ledger: a pomodoro break is free and independent of the manual daily
  allowance.
- The session's phase machine lives in `State.pomodoro: Option<PomodoroSession>`
  and is advanced once per scheduler tick.

```
PomodoroSession {
    block_id: u64,
    focus_secs: u64,
    break_secs: u64,
    cycles_total: u32,   // number of focus intervals in the set
    cycle_index: u32,    // 0-based index of the current focus interval
    phase: PomodoroPhase,      // Focus | Break
    phase_ends_unix: u64,
}
enum PomodoroPhase { Focus, Break }
```

`#[serde(default)]` on `State.pomodoro` so old state loads; the session
persists across a daemon restart (in-flight pomodoro resumes on reload,
exactly like an in-flight block).

## Lifecycle (daemon)

- **`StartPomodoro { block_id, focus_secs, break_secs, cycles }`** IPC:
  - Gated on the `pomodoro` feature (config/activation-time gate, like the
    others). NOT settings-lock gated — starting is always allowed, same as
    `StartBlock`.
  - Refuse if a pomodoro is already running, if the block is already active,
    or if the block doesn't exist. Validate bounds (focus 1–180 min, break
    1–60 min, cycles 1–12) — reject out of range.
  - Create the `PomodoroSession` (phase = Focus, cycle_index = 0,
    phase_ends = now + focus_secs) and push an `ActiveBlock`
    (originator = Pomodoro, `ends_at_unix` = now + the whole set's wall-clock
    length `focus*cycles + break*(cycles-1)` as a hard backstop, break_until =
    None, `apps_enforced`/`lock` snapshotted exactly as `StartBlock` does).
- **`advance_pomodoro`** in the scheduler tick (pure over `(session, active,
  now)` so it is unit-testable): when `now >= phase_ends`:
  - *Focus just ended, more cycles remain* → enter Break: set the pomodoro
    block's `break_until_unix = now + break_secs`, phase = Break, phase_ends =
    now + break_secs.
  - *Focus just ended, last cycle* → the `ActiveBlock.ends_at_unix` (= set end)
    has now been reached, so `reconcile` step 1 drops it and records the
    `FocusSession` through the existing path; clear `State.pomodoro`.
  - *Break just ended* → cycle_index += 1, phase = Focus, phase_ends = now +
    focus_secs (reconcile step 4 independently clears the elapsed break_until;
    both converge — document the ordering).
  - **Prune**: if the pomodoro's `ActiveBlock` is gone (expired, or the block
    was force-ended), clear `State.pomodoro` — same discipline as
    `prune_break_challenges`.
- **`StopPomodoro {}`** IPC (Hybrid): allowed only while phase == Break;
  during Focus return an error ("can't stop during a focus interval — end it
  during a break"). On stop: clear `State.pomodoro` and end the ActiveBlock
  (set `ends_at_unix = now` so reconcile drops + records it, or drop directly
  and record). Ungated (like `TakeBreak`).

### Interactions
- **Manual `TakeBreak` is refused on a pomodoro-driven block** — the pomodoro
  owns break scheduling. Add the guard in the `TakeBreak` arm (Pomodoro
  originator → refuse with a clear message); the GUI hides the manual break row
  for it.
- **Stats**: the pomodoro `ActiveBlock` records ONE `FocusSession` at end,
  `origin = Pomodoro`, duration = the session's wall-clock span (includes the
  auto-breaks, consistent with how a normal block-with-breaks already records).
  Noted tradeoff: this counts break minutes as focus; per-interval crediting is
  deferred (keeps the recording path single-choke-point).

## Wire additions (core)
- `Request::StartPomodoro { block_id, focus_secs, break_secs, cycles }`,
  `Request::StopPomodoro {}`.
- `Status` gains `pomodoro: Option<PomodoroStatus>` (phase, phase_ends_unix,
  cycle_index, cycles_total, block_id) so the GUI can render the running
  session; add the field to the daemon's status builder and the GUI `StatusOut`.
- `Originator::Pomodoro`; `Origin::Pomodoro` (snake_case `pomodoro`).
- `State.pomodoro: Option<PomodoroSession>` (`#[serde(default)]`).

## GUI (clarity is the priority)
A **Pomodoro** tab, shown only when licensed (same gating as the Stats tab;
daemon stays the authority):
- **Setup** (no session running): a saved-block dropdown, focus / break /
  cycles inputs (defaults 25 / 5 / 4), an estimated-total readout, Start.
- **Running**: a large phase banner — "Focus 2 of 4 — 18:42" or "Break —
  04:12" — a cycle progress row (filled/remaining dots), the driven block name,
  and a plain-language statement of the commitment rule. The **End session**
  button is disabled during Focus (tooltip "Available during breaks") and
  enabled during Break. Countdown driven by the status poll like the Status
  tab.
- **Status tab**: label the pomodoro-driven active block "(pomodoro)" the way
  scheduled blocks show "(scheduled)", and suppress its manual break row.

## Testing
- Pure `advance_pomodoro`: focus→break→focus transitions, cycle increment,
  last-cycle end, break-elapsed resume, and the prune-when-active-gone case —
  all clock-free over `(session, active, now)`.
- `StartPomodoro` gating (unlicensed → feature message), bounds validation,
  refusal when already running / block already active.
- `StopPomodoro` refused during Focus, allowed during Break.
- `TakeBreak` refused on a Pomodoro-originated active.
- Session records exactly one `FocusSession` with `origin = Pomodoro`.
- Restart: an in-flight pomodoro reloads and resumes; no false end.

## Open choices baked in (revisit if wrong)
- **Reuse `break_until_unix` for auto-breaks** (no allowance consumption) —
  fewest moving parts, and the scheduler already resumes on its elapse.
- **One `FocusSession` per session** (break-inclusive) — matches existing
  block-with-breaks semantics; per-interval focus crediting deferred.
- **No long break** after the set — the session ends at the last focus (you can
  stop at the preceding break anyway), so a trailing long break is moot in v1.
- **Single concurrent pomodoro** — one session at a time; a second `Start` is
  refused while one runs.

## What shipped (all commits gated on ./scripts/check.sh)

- `0dec487` premium: core + daemon. `Originator::Pomodoro` + `Origin::Pomodoro`;
  `PomodoroSession`/`PomodoroPhase`/`PomodoroStatus`; `State.pomodoro`; pure
  `advance_pomodoro` run before reconcile in the tick (persist-on-change);
  `StartPomodoro` (gated on `pomodoro`, bounds-validated) / `StopPomodoro`
  (Hybrid: refused mid-focus); `TakeBreak` guard; one break-inclusive
  `FocusSession` recorded via reconcile step 1's existing choke point;
  `Response::Status.pomodoro`. Unit tests for the phase machine, bounds,
  gating, and the stop rule.
- `6e243f4` gui: the Pomodoro tab — setup (block + focus/break/cycles + total
  estimate) and a running view built for clarity: phase-countdown banner
  (green during breaks), cycle dots, the commitment rule stated in plain words
  and always visible, and an End-session button loudly disabled during focus /
  enabled during breaks. Status tab labels the block "(pomodoro)" and hides its
  manual break row. `start_pomodoro`/`stop_pomodoro` at all three ACL sites.

## Live verification (Fedora 44, 2026-07-17, daily driver)

| Check | Result |
|---|---|
| Out-of-bounds start (10 s focus) rejected with a clear message | PASS |
| Valid start → Focus, cycle 0/N, block enforced | PASS |
| `StopPomodoro` **refused mid-focus** | PASS |
| Manual `TakeBreak` refused on a pomodoro-driven block | PASS |
| Daemon-driven **focus → break** transition; enforcement lifted on the break | PASS |
| `StopPomodoro` **allowed during a break**; session cleared | PASS |
| Exactly one `origin=pomodoro` `FocusSession` recorded | PASS |
| Natural full-set completion records one session of the exact set span (180 s) | PASS |
| **Daemon restart**: an in-flight session resumes mid-focus (absolute `phase_ends`), block still enforced, no false end recorded | PASS |

Testing note: the restart test must use a set longer than the restart gap — a
short set (e.g. 60/60×2 = 3 min) completes NATURALLY before a hand-timed
restart, which looks like a "lost session + false end" but is correct
completion. Re-run with a 10-minute focus interval confirmed clean resume.

## Not in this milestone
Per-interval focus/stat crediting, a long-break-every-N-cycles rhythm, saved
pomodoro presets/templates, and desktop notifications on phase changes
(deferred; the GUI banner + tray tooltip are the v1 signal).
