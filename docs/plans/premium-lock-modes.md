# Premium lock modes milestone (B2.a, `premium` branch)

Status: **implemented, reviewed, and live-verified** (2026-07-16).

The first of the three B2 capabilities whose feature keys were baked into
every token at the licensing ceremony (`lock_modes`, `usage_stats`,
`pomodoro` — see `premium-licensing.md`). Lock modes make *taking a break*
on an active block harder, per block, so a block can be genuinely
hard to wriggle out of in the akratic moment. Master stays the free v1; this
lives on the `premium` branch alongside B1.

## What a lock mode is

`Block.lock: LockMode` (`crates/core`, `#[serde(rename_all = "snake_case")]`,
`#[serde(default)]` → `Normal` for pre-field records):

- **`normal`** — breaks work as configured, subject only to the daily
  allowance. The only mode the free tier can save.
- **`password_breaks`** — a break requires an active settings-unlock window.
  Deliberately reuses the existing unlock discipline (same window, same copy,
  same GUI dialog), so no new auth surface.
- **`challenge_breaks`** — a break requires retyping a random 40-char string
  the daemon issues, by hand.

There is deliberately **no `NoBreaks` variant**: an
`allowance_secs_per_day == 0` already makes every break fail and hides the
break row entirely, so "no breaks at all" is free and needs no mode. Do not
re-add one.

## Decisions baked in

1. **Modes are gated at SAVE time, enforced from an activation snapshot.**
   `lock_modes` is checked only when a block is added/updated (like
   `app_blocking`). `ActiveBlock.lock` is snapshotted at activation from the
   saved block — exactly like `apps_enforced`. A mid-block edit or license
   change can therefore never *soften* a running block's break rules; the
   snapshot can only make a running block stricter than the current saved
   config, never weaker. `break_gate` reads the snapshot, never the saved
   block.
2. **The break decision is license-free.** The mode was licensed when the
   block was saved; a later downgrade must not start *blocking breaks* on an
   already-saved block. `break_gate` takes no license argument.
3. **Grandfathering mirrors app-list gating** (`update_needs_lock_license`):
   keeping the saved premium lock through an unrelated edit is free (editing a
   grandfathered block's domains must not brick it), and clearing back to
   `Normal` is always free (removing configuration is free). Only
   *introducing* a premium lock, or *changing* one saved premium lock into a
   different premium lock, needs the feature.
4. **Challenges live in the daemon, never the GUI.** `GetBreakChallenge`
   issues a fresh string and stores it in `Daemon.break_challenges`
   (`Mutex<HashMap<block_id, String>>`), overwriting any previous one for that
   block — only the most recently issued string is honoured. The GUI is
   unprivileged and spoofable; it only displays and echoes.
5. **Match is trimmed + case-sensitive.** `challenge.trim() == pending` — a
   trailing newline from the terminal or a stray paste must not fail an honest
   user, but the case must be retyped exactly (the case *is* the friction).
6. **A matched challenge is single-use.** Consumed on success so it cannot be
   replayed. A *rejected* challenge is NOT consumed — the displayed string
   stays live and retyping it is a valid retry.
7. **Challenges are retired when their block deactivates**
   (`prune_break_challenges`, scheduler tick). Without this a user could bank
   a challenge while calm and spend it in a weak moment against a block that
   has since ended and restarted — a replay hole caught in review before the
   commit landed.
8. **Unambiguous alphabet.** 40 chars drawn from a set with no `0/O/o` or
   `1/l/I`, because a human retypes it. Honest about what it is: friction, not
   security. A user who scripts the socket can defeat it the same way they
   could `kill` the daemon as root — out of the akrasia-only threat model.

The `break_gate` decision table (pure, fully unit-tested):

| snapshot lock | condition | result |
|---|---|---|
| `normal` | — | break proceeds |
| `password_breaks` | no settings password set | refuse: "need a settings password" |
| `password_breaks` | password set, not unlocked | refuse: settings-locked (drives the unlock dialog) |
| `password_breaks` | password set, unlocked | break proceeds |
| `challenge_breaks` | `challenge.trim() == pending` | break proceeds, challenge consumed |
| `challenge_breaks` | otherwise (absent/wrong/none pending) | refuse: "challenge response doesn't match" |

## What shipped (all commits gated on ./scripts/check.sh)

- `ffbf261` core+daemon: lock modes. `LockMode` wire enum + `Block.lock` +
  `ActiveBlock.lock` snapshot (landed as one commit — the wire addition
  forces every `ActiveBlock` constructor, so a split would not compile
  standalone); `GetBreakChallenge`/`TakeBreak.challenge` IPC; save-time
  `lock_modes` gate in AddBlock/UpdateBlock with grandfathering
  (`update_needs_lock_license`); the pure `break_gate` table;
  `generate_challenge` (40 chars, unambiguous alphabet); challenge store on
  `Daemon`; `prune_break_challenges` in the scheduler tick. Tests: gate
  matrix, break-gate matrix (both modes), challenge length/alphabet/
  uniqueness, TakeBreak through dispatch for every branch, GetBreakChallenge
  arm (issues/stores/overwrites/round-trips), snapshot-not-saved-block, and
  the prune test.
- `7088981` gui: lock-mode selector in the new-block form; the
  password-lock "no key" non-blocking warning; break-row branching on the
  `ActiveBlock.lock` snapshot; the challenge dialog (fetch-display-echo, text
  `user-select:none`, paste/drop refused, submit gated on typed length);
  `statusInteractionBusy()` extended so the 5s status poll can't rebuild the
  break row out from under an open dialog.

## Live verification (Fedora 44, 2026-07-16, daily driver)

| Check | Result |
|---|---|
| Save a block with `challenge_breaks` + allowance via GUI (licensed) | PASS |
| Daemon persists `lock` field (round-trip over IPC) | PASS |
| `ActiveBlock.lock` snapshot = `challenge_breaks` after StartBlock | PASS |
| `GetBreakChallenge` issues a 40-char string; `TakeBreak` with the exact string grants the break | PASS |
| `TakeBreak` with a wrong/absent challenge is refused, string stays live | PASS |
| Challenge dialog appears; text is visible and unselectable; paste refused | PASS |
| Case-sensitive mismatch surfaces the daemon message verbatim in the dialog | PASS |
| On break → domain pulled from `/etc/hosts` (resolves); break ends → `0.0.0.0` re-added (blocked) | PASS |
| Break allowance `0` hides the break row entirely (free "no breaks") | PASS (by construction) |

## Operational lessons / support notes

- **A `normal`-lock break shows no dialog** — the "Take a break…" ellipsis and
  the challenge popup only appear when the *snapshot* lock is non-`normal`. A
  block saved with the lock dropdown left on its default gives a plain break;
  during first testing this looked like "the challenge doesn't show" when the
  block had simply been saved as `normal`.
- **The break row only exists when `allowance_secs_per_day > 0`** on a
  *running* block. No allowance → no button; not active → no button.
- **On break, the block's domains leave `/etc/hosts`** by design
  (enforcement is lifted, not the block ended). "Site not blocked" during a
  break is correct behaviour, not a bug — the entry returns when the break
  expires.
- **40 case-sensitive characters is genuinely error-prone by hand** — that is
  the point of the mode, but expect honest mistypes in support; "request a new
  challenge" is the recovery.

## Not in this milestone

B2.b `usage_stats` and B2.c `pomodoro` (keys already in every token; each
gets its own plan). Preemptive GUI disabling of gated controls beyond the
inline password-lock warning (the GUI still surfaces daemon refusals
verbatim). Any attempt to defend the challenge against a user scripting the
socket (explicitly out of the akrasia-only threat model).
