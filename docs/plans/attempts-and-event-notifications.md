# Blocked-attempt counts, nudges and event notifications — design record

Status: **implemented — live verification pending** (2026-10-02). Designs A
and B of `docs/plans/0.7.0-plan.md` (written 2026-10-01 against `master` at
0.6.0, `cf5e428`), built as work packages 1–4 on branch `0.7.0-dev`, each
package one commit with `./scripts/check.sh` green. This record states the
design as built; where it drifted from the plan is collected under
*Deviations from the plan*, and the live checklist at the end is still to be
run on the owner's machine before the 0.7.0 release (`docs/release.md`).

It supersedes the "domain blocks are not observable" scope decision in
`premium-usage-stats.md` — the instant-breaks proxy (`instant-breaks.md`)
has seen the hostname of every refused connection since 0.4.0, so the
counter that milestone gave up is now honest — and it builds the design note
`block-page-and-notifications.md`: its option D (notify on app kills) and
the attempt signal its option A anticipated, with the block page itself
still unbuilt.

Progress (every package left `./scripts/check.sh` green and was shippable
on its own):

| WP | Scope | Commit |
|---|---|---|
| 1 | core: `ActiveBlock.attempts`, `DayStat.attempts`/`attempts_total`, `LifetimeTotals.attempts`, `UsageStats::credit_attempt`, `Settings.attempt_nudges`, `EventKind`/`RecentEvent`, `Status.recent_events` (one commit with design C/D's core types) | `a48896c` |
| 2 | daemon: `attempts.rs`, `events.rs`, the proxy's `Observe` hook, `enforce::canonical_attempt`, the scheduler drain and credit-driven save, procwatch kills as events, `GetStatus.recent_events`, SIGTERM save | `07b58bc` |
| 3 | GUI Rust: `notify.rs` (`Watch::poll`) replaces the inline watcher, `StatusOut.recent_events` | `1f4242f` |
| 4 | GUI TS/HTML: `logic/attempts.ts`, the active card's count, the Stats tile and list, the nudge toggle, vitest cases | `054430d` |
| 7 | this record, README *Desktop notifications*, BACKLOG and the release-note lines | this commit |

## Context

Two wants from the backlog, one spine. **Attempt counts:** the loopback
proxy already parses the `Host:` header or TLS SNI of every connection it
refuses, so "how often did I reach for reddit.com today" became measurable
without the DNS resolver the usage-stats milestone had rightly refused to
build; the owner wanted the count on the active block, a per-site history
in Stats, and an optional desktop nudge. **Event notifications:** the GUI
only ever announced block start and end (and, since 0.6.0, a new
enforcement fault); breaks ending, pomodoro phases changing and procwatch
closing an app were silent, although all three are the moments a user
wants to hear about.

Constraints inherited from 0.6.0: every new wire field has a serde default
and an "old daemon ↔ new GUI" test; no new daemon-side container is held
across an await (`health`/`forwardable` precedent); nothing new is premium-
gated except what already rides `GetUsageStats`; hostnames never reach a
journal line above `debug!`; no new Tauri commands.

## Design as built

```
listener.rs handle()  --refused host-->  Observe hook (leaf std::Mutex, never awaits)
            enforce::canonical_attempt: `www.x` folds to `x`; a host outside the live
            `enforced` union is discarded (a developer's own loopback line never counts)
                                             |
                       Daemon.attempts: attempts::Buffer (one per host per 10 s, cap 256)
                                             |   drained once per scheduler tick, under `state`
                                             v
   scheduler::apply_attempts — ActiveBlock.attempts += 1 on every active, not-on-break block
   whose hosts lines covered the host · UsageStats::credit_attempt · events.push(Attempt)
procwatch sweep()  --Kill { pid, block_id, label }-->  app_kills_pending + events.push(AppKill)
                                             |
                    GetStatus: recent_events (ring of 32, seq from 1) + active[].attempts
                                             |
GUI status watcher (5 s poll) --> notify::Watch::poll(Snapshot, &Settings) -> Vec<Notice> -> notify()
```

### A. Attempts

- **Where an attempt is born.** `listener::Observe` is the twin of `Decide`:
  called on the accept path with the parsed hostname of every connection
  the proxy refuses, on both probes; never blocks, never takes a tokio lock.
  A forwarded (on-break) connection or one with no parseable hostname
  reports nothing. The existing `debug!(%host, …)` stays the only line that
  logs a hostname.
- **Attribution.** `enforce::sync` refreshes a leaf `enforced` set next to
  `forwardable` — the union of domains it last wrote. `canonical_attempt`
  folds `www.x` to `x` (the hosts file writes both) and drops anything not
  in the union, so only a blocklist entry the daemon is enforcing is ever
  recorded.
- **Buffer** (`crates/daemon/src/attempts.rs`, pure): one attempt per host
  per `WINDOW_SECS = 10` (a page load's burst of connections counts once),
  at most `PENDING_CAP = 256` counted attempts between drains, overflow
  counted as dropped. Per-host memory is bounded by the enforced set.
- **Drain** (`scheduler::apply_attempts`, pure): the tick is the single
  consumer, next to the app-kill drain. Each active block's domains are
  normalized once per drain; `ActiveBlock.attempts` is bumped on every
  active, not-on-break block whose hosts lines covered the host — the entry
  itself, or the bare entry whose `www.` alias it is, so a request for
  `www.reddit.com` credits a block listing `reddit.com` and one listing
  `www.reddit.com` alike; the day's stats are credited through
  `UsageStats::credit_attempt` keyed on the exact entry a block holds; one
  `Attempt` event is pushed, attributed to the lowest matching block id.
- **Storage** (core): `DayStat.attempts: BTreeMap<String, u32>` capped at
  `ATTEMPT_DOMAINS_PER_DAY = 50` entries per day (first come, not the top
  50 — past the cap only `attempts_total` moves, so "other" is the
  remainder), the per-entry detail cleared on rows older than
  `ATTEMPT_DETAIL_DAYS = 30` while the total survives;
  `LifetimeTotals.attempts`; `ActiveBlock.attempts` per run, zero by
  construction on activation. Bound: 30 × 50 entries, tens of KB in
  practice, inside the HMAC-sealed state file.
- **Saving.** Credits no longer wait for an unrelated save: the tick
  persists when something was credited and at least 60 s have passed since
  the last credit-driven save (`attempt_save_due`, pure, threaded through
  `run`'s loop state), and `run_daemon` now catches SIGTERM — what systemd
  sends on `stop` and on an upgrade — next to SIGINT and saves once after
  the select. A crash or SIGKILL loses at most a minute of attempt and
  app-kill counts; a stop or upgrade loses at most one undrained tick.
- **Privacy.** Hostnames stay at `debug!`; the drain's overflow line and
  every `info!`/`warn!` carry counts only. A hostname that reaches a
  notification passed `validate::hostname_shape` (ASCII labels, no
  lookalikes) and `wire_detail`, which strips control characters and the
  zero-width and bidi format characters (U+200B–U+200F, U+202A–U+202E,
  U+2066–U+2069) so a bidi override in a user's own matcher text cannot
  reach a notification.
- **Licensing.** Recording is always on. The per-day and lifetime numbers
  ride `GetUsageStats` (premium, the existing `usage_stats` key — the
  "Sites blocked" tile and the "Most attempted" list). `active[].attempts`
  and `recent_events` ride `GetStatus`, free: the nudge is a notification
  about enforcement in progress, like block start and end.

### B. Events

- `events::Log` is the bounded (`RECENT_EVENTS_CAP = 32`), sequence-numbered
  ring behind `Status.recent_events`, in-memory like `health`: a restart
  empties it and the sequence starts at 1 again. `RecentEvent { seq, unix,
  kind, block_id, detail }`, `detail` at most `MAX_EVENT_DETAIL_CHARS = 64`;
  `EventKind` is `attempt`, `app_kill` or `unknown` (`#[serde(other)]`, the
  `Health` forward-compatibility pattern). The sequence, not the timestamp,
  is the dedup key: two kills in one second are two events.
- procwatch's sweep returns `Kill { pid, block_id, label }` instead of a pid
  set and pushes one `AppKill` event per new kill. `label` is
  `kill_label(matcher)` — the user's own entry (basename, exe file name or
  cmdline pattern), never `/proc` text. The pid dedup (`recently_killed`)
  is unchanged.
- Both event kinds are stamped on the daemon's block clock
  (`schedule-integrity-and-config-export.md`, C2), the same frame as the
  status frame's `now_unix` the GUI judges them against.

### The watcher (`crates/gui/src/notify.rs`)

The decision stays in Rust, in the status watcher that exists precisely so
notifications do not depend on a visible webview (the window hides to the
tray; the task runs for the life of the process). `Watch::poll` takes one
`Snapshot` per successful poll — the daemon's `now_unix`, the active
blocks, the pomodoro status, `health` and `recent_events` — and returns the
notices to show; the loop in `main.rs` shrank to build-snapshot → poll →
notify. Pure: the clock is `Snapshot::now`, there is no IO, and the tests
feed snapshots directly.

| Notice | When | Copy (title / body) | Limit |
|---|---|---|---|
| Block started / ended | id present in this poll and not the last, or the reverse | unchanged | — |
| Break time | pomodoro `focus → break` | "Break time" / "{name}: {N} min break, cycle {i} of {n}" (minutes from the phase end, rounded, at least 1) | once per transition |
| Focus time | pomodoro `break → focus` | "Focus time" / "{name}: cycle {i} of {n}" | once |
| Pomodoro complete | session gone, was in its last focus interval | "Pomodoro complete" / "{name}: {n} cycles done" ("1 cycle") | once; that block's later "Block ended" is suppressed |
| Pomodoro stopped | session gone, was in a break (`StopPomodoro`) | "Pomodoro stopped" / "{name}" | once; "Block ended" suppressed |
| Break ends in 1 min | remaining break crossed `BREAK_WARNING_SECS = 60` between polls | "Break ends in 1 min" / "{name} will be blocked again" | once per `(block, break end)`; a break of a minute or less never warns; pomodoro breaks warn like any other |
| Break over | on break last poll, not this one, block still running | "Break over" / "{name} is blocked again" | once per break; not on pomodoro-driven blocks ("Focus time" covers it) |
| App closed | `app_kill` event with `seq > last_seq` | "App closed" / "GrepFocus closed {label} ({name})" | one per `(block, label)` per `APP_KILL_REPEAT_SECS = 5 min` (a relauncher loops) |
| Attempt nudge | `attempt` event, `notifications && attempt_nudges` | "{host} blocked" / "{N}th attempt this hour · {name}" | one per host per `NUDGE_REPEAT_SECS = 15 min`; N counts the attempts for that host seen in the last `ATTEMPT_COUNT_SECS = 3600` s, including the ones already in the daemon's log when the GUI started and the ones too stale to nudge for |
| Blocking problem | `enforcement_red` edge (moved in from `main.rs` with its test) | "GrepFocus: blocking problem" / the fault | unchanged |

Rules, stated once in the module docs:

- the first successful poll only sets baselines — a GUI started mid-block
  announces nothing that predates it (the attempts already logged this hour
  do seed the nudge's count, silently);
- a failed poll never reaches `poll`, so baselines survive a daemon restart
  or a transient error without a burst on recovery;
- `settings.notifications == false` returns nothing but advances every
  baseline, so turning notifications back on replays nothing; the master
  gates every kind and `attempt_nudges` is the one sub-switch;
- **sequence rule:** events with `seq > last_seq` are new. A newest `seq`
  below `last_seq`, or an empty log, means the daemon restarted: its
  in-memory log holds only what it logged since, so the baseline drops to
  zero and those entries are judged like any other — shown once, never
  replayed;
- entries older than `STALE_EVENT_SECS = 120` are history after a sleep and
  are skipped (they still count towards "Nth this hour"); an entry with an
  empty detail says nothing;
- **pomodoro session after its block:** a session that disappears *after*
  its block already left the active list — the daemon drops an expired
  block a tick before it prunes the session, after a restart or a suspend
  past the set's backstop — is the tail of that block's end, not a
  completion or a stop; and the `suppress_ended` set is pruned to running
  blocks every poll, so no entry can outlive its block and swallow the id's
  next "Block ended".

### Surfaces

- **Status tab:** the active card's meta line gains "blocked N times",
  shown only while `health.proxy` is `holding` — attempts are counted only
  while the proxy owns ports 80 and 443, so a degraded or off proxy shows
  nothing rather than a misleading zero.
- **Stats tab:** a "Sites blocked" tile (lifetime `totals.attempts`) and
  "Most attempted, last 30 days": the top ten hosts with a trailing "other"
  row for attempts no listed host accounts for, a hint under the list
  (`CAP_HINT_TEXT`, interpolating `ATTEMPT_DOMAINS_PER_DAY`) whenever that
  row appears, and the empty state "No blocked attempts recorded yet —
  counted only while the instant-breaks proxy holds ports 80 and 443."
  The arithmetic lives in `logic/attempts.ts` (`topAttempted`,
  `otherAttempts`, `attemptRows`, `timesText`, `blockedTimesText`,
  `nudgeToggle`), which cuts the window at the same `day >= today − 30` as
  core's `compact_attempt_detail` and skips a row with a positive total and
  an empty map (compacted by construction), so neither old history nor a
  one-day local-date skew between GUI and daemon can render a phantom
  "other".
- **Settings tab:** the master's label becomes "Desktop notifications
  (blocks, breaks, pomodoro, closed apps)"; under it the sub-toggle "Also
  nudge when a blocked site is attempted (names the site; at most once per
  site every 15 minutes; needs Instant breaks on)". `Settings.attempt_nudges`
  is daemon-side, default off: it is a sub-switch of `notifications`, which
  the headless watcher reads off the same poll. With the master off the row
  is disabled but keeps showing the stored value and `applySettings` keeps
  sending it, so the preference survives a master off/on round trip;
  `set_settings` sends all three fields. An 0.6.0 GUI's `set_settings`
  omits the field, which resets it to off — the safe direction.
- `types.ts` mirrors the wire with every new field optional (an old daemon
  omits them). The webview never acts on `recent_events`; the Rust watcher
  owns notifications.

## Deviations from the plan

Recorded from the commit bodies; the plan text is left as written.

1. **`attempts.ts` lives in `src/logic/`** (the plan said `src/attempts.ts`),
   under the WP0 module layout, and also owns `blockedTimesText`,
   `nudgeToggle` and `attemptRows`. Its functions **take `today`** rather
   than reading the clock: `get_usage_stats` returns the last 30 *rows*, not
   calendar days, and a row past the detail window keeps only its total
   with the map cleared, so summing every row would have turned old history
   into a phantom "other". The plan's `topAttempted(days, limit)` had no
   cutoff.
2. **Credits are saved within a minute and on SIGTERM** (`attempt_save_due`;
   the SIGTERM handler). The plan let the counters ride the next unrelated
   save, like `credit_app_kills` — which could be hours away on a quiet
   block, and lost on `systemctl stop`.
3. **A `www.` request credits every block whose hosts lines matched** — the
   bare entry and an explicit `www.` entry alike — and the day's stats are
   keyed on the exact entry the block holds. The plan credited blocks "whose
   canonical domains contain host", which would have skipped a block that
   listed `www.reddit.com` itself.
4. **The restart rule shows post-restart events** instead of swallowing them.
   The plan reset `last_seq` on a lower newest `seq` and emitted nothing for
   that poll; as built the baseline drops to zero and the entries — all
   logged since the restart, by construction of the in-memory log — are
   judged like any other, shown once and never replayed. The 120 s staleness
   rule still bounds what can show.
5. **The pomodoro-session-after-block guard and the pruning of
   `suppress_ended`** were added during WP3 (not in the plan's table): without
   them a session pruned a tick after its expired block produced a false
   "Pomodoro complete", and a suppression entry could swallow the block's
   next "Block ended" a day later.
6. **"Break ends in 1 min" fires for pomodoro breaks too** (the plan's table
   left it implied; `break_warning_also_fires_for_pomodoro_breaks` pins it),
   while "Break over" still defers to "Focus time" on pomodoro-driven blocks.
7. **`wire_detail` strips the zero-width and bidi format characters** as well
   as the controls the plan named.
8. The nudge toggle's label says what it does (names the site, 15-minute
   limit, needs Instant breaks) rather than the bare "attempt nudges" row the
   plan sketched; the "What it does" README bullet and the *Known limits*
   entry on attempt counting landed with this record rather than WP4.

## Rejected alternatives

- **An mpsc channel from the proxy to the scheduler.** A channel still needs
  a consumer task, the dedup has to live somewhere before the state lock,
  and the tick is already the consumer for procwatch's counter — the leaf
  mutex is the `app_kills_pending` shape with a dedup window in front.
- **A GUI-local file for `attempt_nudges`** (the update-check precedent).
  That file exists because the update preference governs the GUI's own
  network contact; a nudge is about daemon events the headless watcher
  reads off `get_status`, and a second source would have made the watcher
  consult two. Cost accepted: the sub-switch passes the settings-password
  gate like `notifications`.
- **A TypeScript watcher (`notify.ts`) for vitest's sake.** It would either
  double-fire next to the Rust block start/end path or tie notifications to
  a hidden webview's timers. The pure function is unit-tested in Rust.
- **A per-kind notification matrix.** `SetSettings` replaces the object
  wholesale, so every extra bool is another field an older GUI silently
  resets; pomodoro, break and app-closed notices are one per transition and
  clearly wanted when notifications are on. Attempts are the only chatty
  kind and the only one naming a site, hence the single sub-switch.
- **Timestamps as the event dedup key.** Two kills in one second are two
  events; a per-run sequence costs nothing and makes a restart detectable
  without a boot id.
- **Swallowing the first poll after a daemon restart** (the plan's rule) —
  see deviation 4.
- From the older design note, still rejected: a local CA for an HTTPS block
  page, a browser extension. The block page on `:80` remains unbuilt; the
  proxy's fixed `403 no-store` page is what a plain-HTTP visit sees.

## Tests

- core (`a48896c`): `credit_attempt_caps_domains_and_keeps_total`,
  `credit_attempt_compacts_detail_older_than_30_days`,
  `credit_attempt_bumps_lifetime_total`, `day_stat_without_attempts_deserializes`,
  `active_block_without_attempts_defaults_to_zero`,
  `lifetime_totals_without_attempts_deserialize`,
  `old_settings_without_attempt_nudges_defaults_off`,
  `status_without_recent_events_still_deserializes`, the `EventKind`
  unknown-tag fold and `set_settings_wire_tag_round_trips` with the third
  field.
- daemon (`07b58bc`, 277 → 300 tests): `listener.rs`
  `a_refused_http_connection_is_observed_once`, `…_tls_…`,
  `a_connection_with_no_hostname_is_not_observed`,
  `a_forwarded_connection_is_not_observed`; `attempts.rs`
  `same_host_within_window_counts_once`, `window_elapsed_counts_again`,
  `distinct_hosts_count_separately`, `pending_cap_drops_and_counts`,
  `drain_prunes_stale_last_seen`, `clock_step_backwards_does_not_underflow`;
  `events.rs` `log_is_bounded_and_seq_monotonic`,
  `detail_is_capped_and_printable`; `enforce.rs`
  `canonical_attempt_folds_www_and_rejects_strangers`; `procwatch.rs`
  `kill_label_per_matcher_kind`; `scheduler.rs`
  `attempt_credits_day_totals_active_counter_and_event`,
  `www_alias_credits_every_block_whose_hosts_line_matched`,
  `www_alias_of_mirrors_the_hosts_file`,
  `attempt_save_is_due_a_minute_after_the_last_one`; `ipc.rs`
  `get_status_carries_recent_events`.
- GUI crate (`1f4242f`, 119 → 135 tests), all in `notify.rs` over one
  `Snapshot` builder with no real clock:
  `first_poll_is_silent_and_sets_baselines`, `block_start_and_end_unchanged`,
  `pomodoro_phase_changes_notify_once_each`,
  `pomodoro_completion_replaces_block_ended`,
  `pomodoro_stop_replaces_block_ended`,
  `session_pruned_after_its_block_already_ended_is_not_news`,
  `break_warning_fires_once_on_the_60s_edge_and_never_for_short_breaks`,
  `break_warning_also_fires_for_pomodoro_breaks`,
  `break_over_skips_pomodoro_blocks`,
  `app_kill_events_dedup_by_seq_and_rate_limit`,
  `attempt_nudge_needs_both_toggles_counts_per_hour_and_rate_limits`,
  `daemon_restart_resets_seq_without_replay`,
  `stale_events_after_sleep_are_ignored`,
  `notifications_off_advances_every_baseline`, `red_edge_unchanged`,
  `enforcement_red_mirrors_frontend_rules` (moved), `ordinals_read_right`.
- vitest (`054430d`, 175 → 216 cases): `logic/attempts.test.ts` — ordering
  by count then name, the limit, the window cutoff inclusive at day 30,
  old-daemon rows read as 0, "other" never negative and never from a
  compacted row inside the window, the empty-state sentence, the "other" row
  last and labelled, the hint shown exactly when that row exists, `timesText`
  singular and plural, `CAP_HINT_TEXT` naming the shared constant, the proxy
  gate on the card text, the toggle state matrix.

## Live verification checklist (owner's machine, Fedora, daemon from this build)

1. Block `reddit.com`; Settings diagnostics shows `proxy: holding`.
   `curl -sk https://reddit.com` closes with no bytes; within 2 s
   `get_status` shows `active[0].attempts == 1` and `recent_events` has
   `{seq: 1, kind: "attempt", detail: "reddit.com"}`. A second curl inside
   10 s: unchanged; after 10 s: 2.
2. `curl http://www.reddit.com` counts as `reddit.com` (and, for a block
   listing `www.reddit.com` itself, credits that block too).
   `curl -H 'Host: myapp.test' http://127.0.0.1/` is refused and **not**
   counted, and nothing is logged at info.
3. Firefox loads reddit.com once: one attempt per distinct blocked host, not
   one per connection.
4. Nudges off (default): no notification. On: "reddit.com blocked — 1st
   attempt this hour · {block}"; a second visit inside 15 min: none; after:
   "2nd/3rd…". The toggle row is greyed while the master is off and keeps
   its value across a master off/on.
5. Stats tab: "Sites blocked" tile and "Most attempted" list.
   `systemctl restart grepfocusd` within a minute of the last attempt: the
   counts persist (SIGTERM save); `active[].attempts` also persists across
   the restart for a still-running block. `kill -9` the daemon instead:
   at most a minute of counts is lost.
6. Hold :80 with another server before starting the block → `proxy:
   degraded`, sink 0.0.0.0, no attempts counted, the card shows no count,
   no error.
7. Pomodoro 2 × (1 min focus / 1 min break): "Break time", "Focus time",
   "Pomodoro complete"; no "Block ended". Stop during a break: "Pomodoro
   stopped" only. A 2-min pomodoro break also gets "Break ends in 1 min".
8. Manual 2-min break: "Break ends in 1 min" exactly once around T−60 s,
   "Break over" at the end. A 30-s break: no warning.
9. Premium app block on basename `sleep`; `sleep 1000 &` → "App closed:
   GrepFocus closed sleep (…)"; relaunch within 5 min → silent; `app_kills`
   still increments.
10. Master notifications off → silence; back on → no replay. GUI started
    mid-block with 10 existing events → no burst. Daemon restart
    mid-session → the pre-restart events are not replayed; a kill or
    attempt logged after the restart still arrives once.
11. `journalctl -u grepfocusd -p info` during all of the above contains no
    hostnames.
12. 0.6.0 GUI against the new daemon: Status parses; toggling notifications
    resets `attempt_nudges` to off (expected). New GUI against a 0.6.0
    daemon: no counts, no events, no errors.
13. `./scripts/check.sh` green; `cargo test -p grepfocusd listener` count
    rose from 41.
