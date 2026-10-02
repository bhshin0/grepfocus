# Schedule integrity and configuration export/import — design record

Status: **implemented — live verification pending** (2026-10-02). Designs C
and D of `docs/plans/0.7.0-plan.md` (written 2026-10-01 against `master` at
0.6.0, `cf5e428`), built as work packages 5 and 6 on branch `0.7.0-dev`
(the core half of both in WP1), each commit with `./scripts/check.sh`
green. This record states the design as built; what shipped differently is
collected under *Deviations from the plan*, and the live checklist at the
end is still to be run on the owner's machine before the 0.7.0 release
(`docs/release.md`). Extends `allowance-policies-and-nested-schedules.md`
(the scheduler's reconcile and window functions, which C1 and C3 change)
and, for the wall-clock exceptions the block clock keeps, `premium-licensing.md`
(license expiry on `effective_now`/`high_water_unix`).

Progress (every package left `./scripts/check.sh` green and was shippable
on its own):

| WP | Scope | Commit |
|---|---|---|
| 1 | core: `validate_schedule`/`schedules_equivalent` moved into `core::validate`, `ClockAnchor` on `State`, the `config_doc` module (build, parse, plan) | `a48896c` |
| 5 (C1) | reconcile step 2 deleted: a schedule-started block keeps its snapshotted window end; `update_schedule`/`delete_schedule` pass while it runs | `5fcc55a` |
| 5 (C2) | `clock.rs`: the BOOTTIME-anchored block clock, `Daemon::now()` at every block-timing site, the persisted anchor | `0666e5e` |
| 5 (C3) | windows past midnight up to 24 h, generic window functions, the DST policy, the GUI's `(+1 day)` ranges, continuation segments and the "running now until" hint | `f0321f3` |
| 6 (D) | `ExportConfig`/`ImportConfig`, the document caps and linear dedupe, the GUI's Export/Import… with `config_io.rs`, `logic/config.ts` | `b261491` |
| 7 | this record, README and BACKLOG, the release-note lines; the `importDialog` guard follow-up in `main.ts` | this commit |

## Context

Three ways a block could end sooner than the user had committed to, and one
missing door:

- **Schedule edits ended running blocks.** The scheduler re-read the
  schedule table every tick and ended any schedule-started block whose
  schedule had been disabled, deleted or moved (reconcile step 2). The
  schedule row was a cancel button in disguise — the thing strict mode
  exists to prevent.
- **`sudo date -s '+2 hours'` ended a block on the spot.** Every
  block-timing decision read the wall clock.
- **A window had to end by 24:00**, so "22:00 for 4 h" was refused; the
  evening schedule most people want could not be expressed.
- **No way to carry a configuration** to another machine or keep a copy:
  the state file is sealed with a per-machine HMAC secret, so copying
  `/var/lib/grepfocus` does not work.

Constraints inherited from 0.6.0: serde defaults and old-state tests for
every new field; premium gates applied daemon-side and reused rather than
re-stated; no dialog plugin or other new dependency for the GUI; the only
new Tauri commands are `export_config` and `import_config` (three ACL sync
points).

## Design as built

### C1. A schedule-started block keeps its snapshotted end

The window end was already snapshotted: a fire writes the window's end into
`ActiveBlock.ends_at_unix`, and reconcile step 1 expires on it. Step 2 —
the per-tick re-evaluation of the schedule table — is deleted and the steps
renumbered, so expiry is the only way any block ends, exactly as for `lock`,
`allowance` and `apps_enforced`. No second field: it would only duplicate
`ends_at_unix`.

An edit applies from the schedule's next window. An edit that *extends* the
running window makes it fire again at the old end (step 2, now the fire
step, finds the block gone and the window still open): two sessions in the
usage stats, by design. `update_schedule` and `delete_schedule` stay allowed
while the block runs — with the snapshot no edit can shorten or end it, so
refusing would lock the schedule table for the whole window and buy
nothing; `update_block`'s refusal stays, because the block's content is what
enforcement reads. The GUI's schedule row says "running now until HH:MM —
changes apply from the next window" (landed with C3, which owns the row's
copy).

### C2. The block clock (`crates/daemon/src/clock.rs`)

Every block-timing decision reads `Daemon::now()` — a trusted block clock —
instead of the wall clock: block, break and pomodoro ends, the settings
unlock window, the status frame's `now_unix` (so the GUI's countdown skew
follows the same frame), and the attempt and kill event stamps the GUI
judges against that field. By design **not** on this clock: license expiry
(`effective_now`), `browser_policy`, and the export stamp
(`exported_at_unix` is provenance read on another machine next to the
file's wall-clock name). Schedules still fire by local wall time: stepping
the clock to open a window only starts a block that then runs the window's
remaining length.

Per scheduler tick the clock compares the wall-clock delta with the
`CLOCK_BOOTTIME` delta (`nix` gains the `time` feature). BOOTTIME keeps
counting through suspend — unlike `CLOCK_MONOTONIC`, which an `Instant`
reads — so the two agree exactly when timekeeping was honest, sleep
included, and disagree exactly when the clock was stepped:

- deltas agree within `STEP_TOLERANCE_SECS = 2` → trusted time follows the
  wall clock (NTP slew and leap seconds absorbed), **but the drift absorbed
  this way is capped at 2 s per busy stretch**, not per tick: a root loop
  stepping the clock by 2 s every second would otherwise have run a block
  at double speed, which is exactly the sudo-in-the-moment case the guard
  exists for;
- deltas disagree → trusted time advances by the elapsed (BOOTTIME) delta
  only and the step is logged once ("clock step of +N s detected; block
  timing continues on elapsed time"). A forward step during a block makes
  it end later in real time, never earlier; a backward step changes
  nothing;
- idle (no active block, no pomodoro) → trusted time resyncs to the wall
  clock in both directions and the absorbed budget is handed back. Nothing
  is at stake while idle, and the frame is what the status frame, the
  event stamps and the attempt windows are read in, so a step seen while
  idle must not leave it permanently offset. The guard protects a running
  block only: a forward step while idle can skip an upcoming scheduled
  window or open it with its remaining length, which the README says.

**A schedule fire ends in the same frame.** `ends_at_unix` is the block
clock's now plus the window's remaining length by the wall clock — never
the wall instant the window closes at. With the block clock ahead of a
wall clock that was set back (during a running block, or across a reboot
with a persisted active), a wall-instant end would already be in the past
on the block clock: the active would be born expired, dropped on the next
tick as a one-second session and fired again — a save, a hosts rewrite and
two log lines every second for the whole window. The unlicensed-skip
markers are pruned against the wall clock their window ends are in, for
the same reason.

**Restart continuity.** The scheduler persists a `ClockAnchor { trusted_unix,
boot_secs, boot_id, absorbed_secs }` on every save. A daemon starting in
the same boot (the kernel's `boot_id` matches) resumes from it exactly —
trusted time plus the BOOTTIME elapsed since, with the absorbed budget
still spent (clamped to the tolerance) — however stale the save, and
before the startup retain judges expiry (`drop_expired_active`, pure). So
"step the clock, `kill -9`, let systemd restart" gains nothing, and neither
does "step by 2 s, save, restart" in a loop (with the budget reset on every
restart a 3600 s block ran out after 1200 s). After a reboot the anchor is
stale by construction and the clock seeds from the wall clock clamped to
`high_water_unix`; changing the clock across a reboot is root with
physical access, out of the threat model. The clock is a leaf
`std::sync::Mutex` on `Daemon` like `health`, behind an `Arc` so the
proxy's observe hook and procwatch stamp events in the same frame.

### C3. Windows past midnight

`validate_schedule` and `schedules_equivalent` live in `core::validate` so
the importer and the daemon share one rule set (a schedule name also gets
the block name's rules: no control characters, at most 200 characters).
Only a window's *length* is capped, at 1440 minutes; `start_minute < 1440`
stays. A window belongs to the weekday it starts on: "Mon 23:00 for 2 h" is
in progress at 00:30 on Tuesday iff Monday is selected. With the cap, a
schedule's spill-over tail ends (half-open) no later than its next same-day
window opens, so at most one instance is live per schedule and the
one-active-per-block check stands.

The scheduler's window functions are generic over the zone
(`window_start_date_at`, `schedule_active_at`, `window_end_unix_at`,
`local_instant_at_or_after`) and the end is keyed off the instance's start
date: `window_end_unix_at` is `None` outside the window, reconcile
evaluates it once per schedule, and the same instant is reported before and
after midnight — the unlicensed-skip marker stays stable across the
boundary and a fired block's remaining length does not depend on which
side of midnight it was computed.

**DST policy — never shorter, on both nights.** The end is the later of two
readings: the window's wall-clock end and its start plus its length. A
wall time the fall-back makes ambiguous resolves to the later instant; a
window that ends in or straddles the spring-forward gap keeps its real
length (a skipped wall time steps forward an hour at a time until one
exists, bounded at a day). `chrono-tz` joins the daemon's dev-dependencies
for the Europe/Amsterdam tests.

GUI: schedule rows and the Week grid print "23:00–01:00 (+1 day)"
(`fmtWindowRange`, `logic/format.ts`) instead of a silently wrapped end,
and the grid draws the part after midnight as an arrowed continuation in
the next day's column, laned like any other segment (`windowSegments`,
`segmentLabel`, `segmentTitle`, `layoutDay` in `logic/week.ts`). A row
whose block is running now says until when — the end moved from the
daemon's block clock into the desktop's frame through the status frame's
skew, so a clock step mid-block does not shift it — and that changes apply
from the next window (`logic/running.ts`). The Block list re-renders on the
status poll only when a window has fired or ended (`runningSchedulesKey`),
never over a focused form or a dialog a row opened (`listInteractionBusy`;
the import dialog joined its list in WP7); a rebuild keeps the cards'
expanded disclosures, and one overtaken by a newer call leaves the DOM to
it. The dialog's field parsing is `scheduleFields` in `logic/forms.ts`.

### D. Export / import

**Document** (`crates/core/src/config_doc.rs`, pure): `{ schema: 1,
exported_at_unix, app_version, blocks, schedules }` and nothing else —
`build` takes only blocks and schedules, so the password hash, license,
high-water mark, stats, breaks, actives, pomodoro and settings are excluded
by construction. `parse` refuses a text over `MAX_DOC_BYTES` (8 MiB, under
the wire frame cap), one that is not a GrepFocus export, a missing schema
and a newer schema ("exported by a newer GrepFocus (schema N) — update
first"); unknown top-level keys are tolerated. Document-wide caps, checked
by `parse` and `plan_import` alike: `MAX_DOC_BLOCKS` 1000,
`MAX_DOC_SCHEDULES` 2000, `MAX_DOC_DOMAINS` 50 000, `MAX_DOC_APPS` 5000.
`plan_import` is pure: base = existing (Merge) or empty (Replace); ids
always continue from the current counters — never reused, because the
usage stats and the break history reference block ids; per block in file
order `validate_block` (error prefixed `block "{name}": …`, the same text
as `AddBlock`) and the policy normalization `AddBlock` does; duplicate ids
within the file → error; a name collision against the result set →
"{name} (imported)", then "(imported 2)"… with the suffix cut back to stay
within the name cap (the bookkeeping is linear: a taken-name set plus a
next-suffix counter per base name); per schedule the `block_id` is
remapped (missing → error naming the schedule), `validate_schedule`
applied, and one equivalent to a schedule already in the result set is
skipped and counted, not refused; an empty document is an error.
`validate_block` dedupes domains and app matchers through a seen-set
(`AppMatcher` derives `Hash`), keeping first-occurrence order — the
`Vec::contains` scan it replaced was quadratic, and an import of a few
hundred full blocks ran for over ten seconds under the daemon's state
lock; the largest allowed import now plans in about 0.2 s in a debug
build, which a lock-budget test pins under 2 s.

**Daemon** (`ipc.rs`): `ExportConfig` returns `config_doc::build` over the
saved blocks and schedules, ungated like the two lists it is made of, with
`exported_at_unix` on the wall clock. `ImportConfig { doc, mode }` takes the
parsed document, behind the settings lock; the daemon re-checks the schema
(`check_schema`, shared with the GUI so both say the same thing — a raw
socket client never ran `parse`), refuses Replace while a block or pomodoro
runs ("cannot replace configuration while a block is active"), plans the
import (validation before any feature pitch), then gates every imported
block through `gate_add_block` with the blocks before it counted as saved
so the exact `MSG_BLOCK_CAP`/`MSG_APP_BLOCKING`/`MSG_LOCK_MODES` copy
applies, and any new schedule through `MSG_SCHEDULES`. Only then are
blocks, schedules and both id counters swapped in, and all four are
restored if the save fails — all or nothing by construction. Merge stays
allowed while a block runs: adding never touches an active. The response
is `{ result: "imported", blocks, schedules, renamed, skipped_schedules }`
(`imported_counts`, pure).

**GUI:** `export_config` writes `grepfocus-config-YYYYMMDD-HHMMSS.json` with
`create_new` (never an overwrite) and mode 0600 (block names and domains
are personal) into the XDG download directory — `config_io.rs` is pure:
`download_dir` over `user-dirs.dirs` with quotes and `$HOME` expansion
(`$HOME` alone or before a slash; `$HOMEfoo` is another variable), falling
back to `~/Downloads` then `~`; `export_file_name`; `display_path` — and
returns the `~`-abbreviated path. `import_config` pre-parses with
`config_doc::parse` for a friendly error and sends the typed request. The
Block list tab gets **Export** (no ellipsis: nothing follows the click) and
**Import…**, a hidden `<input type="file">` (WebKitGTK's native chooser, no
dialog plugin) and an import dialog with Merge (default) and Replace, the
latter disabled while anything runs with the reason shown; the import asks
for the settings password like any other change and reports what it added
("Imported 3 blocks and 2 schedules · renamed: Work → Work (imported) · 1
duplicate schedule skipped"). The pure parts — `importFileRefusal`,
`importFileLabel` (sizes in KiB/MiB, the refusal's units), `replaceRefusal`,
`importSummaryText`, `MAX_IMPORT_BYTES` — live in `logic/config.ts`; the
document logic is not repeated in TypeScript. The `Status` fixture the
config, first-run and health tests each carried moved to
`logic/testing/status.ts`, so a new `Status` field is a one-place change.
Three ACL sync points: `generate_handler!`, `build.rs`'s command list,
`capabilities/default.json`.

## Deviations from the plan

Recorded from the commit bodies; the plan text is left as written.

1. **Package order was C1 → C2 → C3** (the plan said C1 → C3 → C2); the
   GUI's "running now until" hint, planned under C1, landed with C3, which
   owns the schedule row's copy.
2. **The absorbed-drift budget is per busy stretch, not per tick**, and it
   is persisted: `ClockAnchor` gained `absorbed_secs` so a resume in the
   same boot comes back with the budget spent. The plan's per-tick
   tolerance would have let a chain of 2 s steps run a block at double
   speed.
3. **A schedule fire's `ends_at_unix` is `now + remaining` in the
   block-clock frame**, not the wall instant the window closes at; the
   skip markers are pruned on the wall clock. The plan's wall-instant end
   produced the born-expired fire loop described above once the clock was
   ahead of a wall clock set back.
4. **The clock is behind an `Arc`** so the proxy's observe hook and
   procwatch's kill events — two stamp sites that landed after the plan was
   verified — stamp in the same frame.
5. **The DST policy is max-of-two-readings** (wall-clock end vs. start plus
   length), which covers a window that *straddles* the gap as well as one
   that ends in it; the plan's "retry naive + 1 h up to 3×" handled only
   the ending-in-the-gap case. The skipped-time step is bounded at a day
   rather than three tries.
6. **The window functions fold into `window_end_unix_at`**, an `Option`
   that is `None` outside the window and keys the end off the instance's
   start date; `schedule_active_at` wraps it. Reconcile evaluates it once
   per schedule.
7. **The running-now hint is computed in the desktop's frame** from the
   status frame's skew rather than printed from the daemon's `ends_at_unix`
   directly, so a clock step mid-block does not move it; and the Block list
   re-renders on the poll only when a window fired or ended, instead of
   threading `activeEndsAt` through every `refreshList`.
8. **Document-wide caps (`MAX_DOC_DOMAINS`, `MAX_DOC_APPS`) and the linear
   dedupe in `validate_block`** came from the WP6 review: the per-block caps
   alone allowed a 16 MiB file whose import held the state lock for over
   ten seconds.
9. **The export file is 0600** (the plan said only `create_new`), its path
   is shown `~`-abbreviated, and `exported_at_unix` is an explicit
   wall-clock exception to C2.
10. **`check_schema` is factored out of `parse`** so the daemon's re-check
    and the GUI's pre-parse share the strings; `imported_counts` is a pure
    helper with a unit test because the save-succeeds branch never runs on
    a dev box.
11. **The import dialog disables Replace itself** while anything runs
    (`replaceRefusal` over the last status), on top of the daemon's refusal
    the plan relied on.
12. **`logic/config.ts` has vitest cases** for the GUI's own strings and the
    Replace decision. The plan's "do not add vitest for export/import" still
    holds for the document logic, which is Rust-only.
13. WP7 added `importDialog` to `listInteractionBusy` and
    `statusInteractionBusy`: the poll-driven list rebuild must not run
    behind the import dialog either.

## Rejected alternatives

- **A `schedule_window_end_unix` field on `ActiveBlock`.** `ends_at_unix`
  already is the snapshot; a second field would be a second source of
  truth.
- **Refusing `update_schedule`/`delete_schedule` while the block runs.**
  Buys no safety once the snapshot carries, and locks the schedule table
  for up to 24 h.
- **A pure `Instant` clock.** `CLOCK_MONOTONIC` stops during suspend; a
  laptop asleep two hours would run every block two hours long.
- **A wall-delta-only heuristic.** Cannot tell sleep from `date -s`.
- **Per-tick tolerance** (the plan's rule) and **resetting the absorbed
  budget on restart** — both defeated by a loop, see deviation 2.
- **A wall-instant end for schedule fires** — the born-expired loop, see
  deviation 3.
- **A fake `TimeZone` in tests instead of `chrono-tz`.** Forty lines of
  test double versus a dev-dependency that tests the real zone data.
- **`<a download>` of a Blob for export.** WebKitGTK's default download
  handler saves silently into XDG Downloads, fails silently on an existing
  name, and offers no Save-As without the dialog plugin; the Rust write
  costs the same zero dependencies and says where the file went.
- **`tauri-plugin-dialog`** (a new crate and ACL entries for a Save-As)
  stays the option if a real Save-As is ever wanted.
- **Skipping a block whose name is taken** rather than renaming — lossy and
  invisible; names are not keys.
- **Reusing block ids on Replace** — the usage stats and the break history
  reference them.
- **Refusing an equivalent schedule** as `AddSchedule` does — would fail a
  whole re-import of a file that was exported from the same machine.

## Tests

- core (`a48896c`, `b261491`): `validate.rs`
  `validate_schedule_accepts_midnight_span_and_caps_at_24h`,
  `validate_schedule_rejects_each_kind`, `schedules_equivalent_ignores_name`;
  `lib.rs` `state_without_clock_anchor_still_deserializes`,
  `clock_anchor_round_trips` (covers `absorbed_secs` and an anchor written
  before the field existed); `config_doc.rs` `build_then_parse_round_trips`,
  `doc_has_exactly_five_top_level_keys`,
  `parse_rejects_garbage_oversize_and_newer_schema`,
  `doc_without_schedules_key_parses`, `plan_reassigns_ids_and_remaps_schedules`,
  `plan_renames_collisions_with_suffix_and_counter`,
  `plan_rename_never_exceeds_the_name_cap`,
  `parse_rejects_too_many_blocks_and_schedules`,
  `plan_import_rejects_too_many_blocks_and_schedules`,
  `parse_rejects_too_many_domains_and_apps`,
  `plan_import_rejects_too_many_domains_and_apps`,
  `plan_import_at_the_entry_caps_fits_the_lock_budget`,
  `plan_skips_equivalent_schedules`,
  `plan_replace_ignores_existing_but_keeps_counters`,
  `plan_rejects_duplicate_ids_and_dangling_block_refs`, `plan_rejects_empty_doc`,
  `plan_prefixes_validation_errors_with_the_name`,
  `import_mode_serializes_snake_case`.
- daemon (C1, 300 → 304): `disabled_schedule_does_not_end_its_running_block`,
  `deleted_schedule_does_not_end_its_running_block`,
  `moved_window_does_not_end_its_running_block`,
  `schedule_end_records_a_schedule_origin_session` (now by expiry),
  `shortened_schedule_runs_to_snapshotted_end`,
  `extended_schedule_refires_at_snapshotted_end`;
  `update_schedule_passes_while_its_block_runs`,
  `delete_schedule_passes_while_its_block_runs`.
- daemon (C2, 304 → 323): `clock.rs`
  `seed_takes_the_wall_clock_clamped_to_the_floor`,
  `tracks_wall_when_deltas_agree`, `suspend_counts_as_elapsed`,
  `forward_step_while_busy_advances_by_elapsed_only`,
  `backward_step_while_busy_keeps_advancing`,
  `idle_resyncs_to_wall_both_directions`, `busy_never_resyncs_across_ticks`,
  `tolerance_boundary_is_two_seconds`,
  `small_steps_cannot_outrun_elapsed_time_by_more_than_the_tolerance`,
  `resume_same_boot_adds_boot_elapsed`,
  `resume_other_boot_seeds_from_wall_clamped_to_high_water`,
  `now_at_adds_boot_elapsed_between_ticks`,
  `anchor_carries_the_tick_and_the_boot_id`,
  `resume_same_boot_keeps_the_absorbed_budget`, `read_returns_the_live_clocks`,
  `boot_id_is_the_kernel_uuid`; `scheduler.rs`
  `schedule_fire_ends_in_the_block_clock_frame`,
  `skipped_fire_markers_are_pruned_by_the_wall_clock_not_the_block_clock`;
  `main.rs` `expired_active_retain_uses_the_resumed_clock`.
- daemon (C3): `wrap_active_before_midnight_on_start_day`,
  `wrap_active_after_midnight_only_if_start_day_selected`,
  `wrap_end_is_same_instant_before_and_after_midnight`,
  `wrap_window_fires_and_expires_across_midnight_in_reconcile`,
  `wrap_skipped_fire_is_logged_once_across_midnight`,
  `full_day_window_boundary_is_half_open`, `end_at_1440_is_next_day_midnight`,
  `dst_gap_end_keeps_real_duration`,
  `dst_gap_straddling_window_keeps_real_duration`,
  `dst_overlap_end_prefers_later_instant` (Europe/Amsterdam via `chrono-tz`).
- daemon (D, `ipc.rs`): `export_config_returns_only_blocks_and_schedules`,
  `import_config_is_gated_by_the_settings_lock`,
  `import_config_refuses_newer_schema`,
  `import_merge_free_tier_cap_with_exact_copy`,
  `import_replace_one_block_passes_free_cap`,
  `import_apps_and_lock_gated_like_add_block`, `import_schedules_gated_free`,
  `import_validation_precedes_premium_gate`,
  `import_replace_refused_while_active_and_during_pomodoro`,
  `import_merge_passes_while_a_block_is_active`,
  `import_dangling_schedule_leaves_state_untouched`,
  `imported_counts_subtract_what_was_already_saved`.
- GUI crate (`config_io.rs`):
  `download_dir_reads_the_xdg_entry_with_home_expansion_and_quotes`,
  `download_dir_ignores_comments_and_unusable_entries`,
  `download_dir_falls_back_to_downloads_then_home`,
  `export_file_name_is_dated_to_the_second`, `display_path_abbreviates_home`,
  `write_new_creates_the_file_private`, `write_new_refuses_an_existing_file`.
- vitest: `format.test.ts` (`fmtWindowRange`), `week.test.ts`
  (`windowSegments`, continuation lanes, labels and titles),
  `forms.test.ts` (`scheduleFields`), `running.test.ts`, `config.test.ts`
  (the file label and size guard, the Replace decision, the summary line).
  262 cases in nine files on this branch.

## Live verification checklist (dev box, `[user]` = sudo)

**Schedule integrity**

1. `./scripts/check.sh`; `[user] sudo ./packaging/upgrade.sh`.
2. Mid-window edits: a schedule on block X at now+1 min for 5 min → fires
   ("(scheduled)" banner, 5:00 countdown); Disable → countdown unchanged,
   the row says "running now until HH:MM — changes apply from the next
   window"; Edit start +2 h → unchanged; Delete → unchanged; the block ends
   at the original minute; Stats shows one schedule session. Repeat with a
   3-min window extended to 6 min at 1 min in → ends at 3 min, a new
   active fires at once (two sessions).
3. Spanning window: add "23:00 for 2 h" on today's weekday → accepted; the
   row reads "23:00–01:00 (+1 day)"; the Week grid shows the 23–24 segment
   today and a "↳ 00:00–01:00" segment tomorrow; `list_schedules` over the
   raw socket shows `duration_minutes: 120`. Evening check: "23:58 for
   4 min" → the journal's "expired active blocks" at 00:02, one 4-min
   session, no re-fire at 00:00.
4. Clock: `[user] timedatectl set-ntp false`; start a 10-min manual block;
   `[user] sudo date -s '+2 hours'` → journal "clock step … detected", the
   Status countdown unchanged on the next poll; `sudo date -s '-2 hours'`
   → no change; the block ends at the right real minute.
   `[user] timedatectl set-ntp true` afterwards.
5. Suspend: a 5-min block, `systemctl suspend` for ~3 min, resume → ~2 min
   left, ends on time.
6. Restart mid-lag: during step 4's lag, `[user] sudo systemctl restart
   grepfocusd` → the journal reports the anchor resumed, the block persists
   to its real end; `grep clock_anchor` in `sudo cat
   /var/lib/grepfocus/state.json` after any save shows `absorbed_secs`.
7. Downgrade note: an older daemon given the spanning schedule enforces
   only the part before midnight and refuses to re-save it (README,
   *Updating*).

**Export / import**

1. With ≥ 2 blocks (one with apps, a lock and a rolling policy) and 2
   schedules (one spanning midnight): Export → the message names
   `~/Downloads/grepfocus-config-….json`; `ls -l` shows `-rw-------`;
   `jq 'keys'` → exactly `app_version, blocks, exported_at_unix, schedules,
   schema`; `grep -ci 'password\|license\|stats\|high_water'` → 0.
2. Merge the same file with a password set and locked → the unlock dialog,
   then "Imported 2 blocks and 2 schedules · renamed: …"; the cards show
   "(imported)"; the schedules are attached to the new cards; the Week grid
   shows both copies.
3. Hand-edit a domain to `reddit.com\n0.0.0.0 evil` → the daemon's exact
   `validate_block` text prefixed with the block name; `list_blocks`
   unchanged; `/etc/hosts` untouched.
4. Free tier (License → Remove, then re-activate afterwards): merge →
   `MSG_BLOCK_CAP` verbatim, nothing imported.
5. Replace while a 2-min block runs → the dialog's Replace is disabled with
   the reason; over the raw socket → "cannot replace configuration while a
   block is active"; after it ends → Replace works, the old cards are gone,
   the new ids are higher than any old id, Stats still lists the old
   sessions.
6. Raw socket: `{"method":"import_config","doc":{"schema":2,
   "exported_at_unix":0,"app_version":"x"},"mode":"merge"}` → "exported by
   a newer GrepFocus"; the same with `"schema":1` → "the file contains no
   blocks or schedules".
7. The poll-driven list rebuild stays away while the import dialog is open:
   let a scheduled window fire with the dialog up → the dialog and the
   chosen file survive; the list rebuilds after Cancel.
