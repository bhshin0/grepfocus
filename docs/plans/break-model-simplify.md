# Break-model simplification + notifications toggle (`break-model-simplify`)

Status: **implemented; live verification pending** (2026-07-25).

Follows a live-test finding: after taking a break, a blocked site stayed
unreachable for the whole break. Root cause was not a bug in the break path —
it was the browser's own in-process DNS cache (~60 s in Chrome, up to ~120 s in
Firefox), which no external process can flush. A 60-second rolling break was
consumed almost entirely by that cache, so the break looked broken.

Three things came out of that:

## 1. The visit-detection listener was shelved

The loopback listener (detect a blocked visit via `Host:`/SNI, then prompt for a
one-click break) was built, security-audited, and works — but it does **not**
solve the reported problem: the ~60 s lag is inherent to hosts-file blocking and
is identical whether the sink is `0.0.0.0` or `127.0.0.1`. The listener's only
real cost was a root process on ports 80 and 443. With no matching benefit for
this problem, the whole stack (~2,400 lines) was moved to branch
**`visit-detection-shelf`** rather than carried in every build and every future
audit. It is one checkout away if per-domain stats or the one-click prompt are
wanted later. The cacheable-`200` fix (now `403` + `Cache-Control: no-store`)
lives on that shelf so the preserved code is correct.

Kept from that line, because both stand alone:
- the **DNS cache flush** on enforcement change (`crates/daemon/src/dns.rs`) —
  it flushes the *system* resolver, an honest partial help that predates the
  listener and improves the plain manual break flow;
- the **notifications off-switch** (below).

## 2. Rolling breaks are now all-or-nothing

`RollingWindow` no longer offers a minutes box. One click grants the whole
available budget: "5 minutes per hour" means you take the 5 minutes in one
piece, not slices that each vanish into the DNS cache.

- **Daemon is the authority.** `TakeBreak` runs the request through
  `effective_break_request(policy, requested)`, which returns the policy's full
  `secs` for `RollingWindow` and the client's value otherwise. `compute_grant`
  is untouched — its existing `grant = requested.min(remaining).min(ends_at −
  now)` then gives **grant-what-fits-charge-what-fits**: a block with less time
  left than the budget grants and charges only what fits, via the `ends_at` cap.
- `PerDay` keeps its minutes input (a daily budget is the one you genuinely want
  to spend in pieces). `PerBreak` is unchanged.
- The GUI rolling row drops `.break-min` and shows a single
  `Take your N min break` button; exhausted/`next_free` messaging is preserved.
- `next_free_secs` / tie-summing in the reducer is left in place — still correct
  for any legacy partial records, just rarely exercised now.

## 3. Notifications can be turned off

Block start/end notifications fired unconditionally with no off switch. New
`Settings { notifications: bool }` on `State` (`SetSettings` IPC, `set_settings`
Tauri command at all three ACL sync points, a Settings-tab checkbox), and the
poller's `notify` calls are gated on it. **`Settings::default` is hand-written
with `notifications: true`** — a derived default would be `false` and would
silently mute every existing user on upgrade; a compat test pins that an old
`State` with no `settings` key loads with notifications on.

An honest one-line hint now sits on every break row: *"A break can take up to a
minute to take effect in a tab that's already open — reload the page if it
doesn't."* This is the real answer to the reported symptom.

## What shipped (all gated on `./scripts/check.sh`)

- `d8578cd` daemon: flush DNS caches when the enforced domain union changes
  (cherry-picked from the shelved line — the one piece of it worth keeping).
- `6a9ae4c` core+daemon+gui: notifications off-switch.
- `15a460c` core-adjacent+daemon+gui: rolling all-or-nothing + the lag hint.

Branch `break-model-simplify` is built on `allowance-policies`; neither is
merged to `master` yet. The listener line is preserved on
`visit-detection-shelf`.

## Live verification (pending a deploy)

| # | Check |
|---|---|
| 0 | Rolling block: the break row shows a single "Take your N min break" button, no minutes box |
| 1 | Taking it grants the whole budget; a near-expiry block grants only what fits |
| 2 | `PerDay` block still shows the minutes input and splits as before |
| 3 | After a break, the site loads within ~a minute (reload); the hint sets that expectation |
| 4 | Notifications off → no block start/end notifications; on → they fire |
| 5 | Upgrade over existing state: notifications default ON, blocks/licence intact |

## Not here

The listener, visit detection, per-domain stats (all on the shelf). Any attempt
to flush the browser's in-process DNS cache — not possible from outside the
browser; the hint is the honest handling.
