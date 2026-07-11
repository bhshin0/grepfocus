# Premium licensing milestone (B1, `premium` branch)

Status: **implemented, reviewed, and live-verified** (2026-07-11).

The daemon-side half of the licensing contract frozen in
`grepfocus-web/lib/license.ts`: Ed25519 token verification, persistence,
IPC, feature gating, and a GUI license tab. Master stays the free v1; this
lives on the `premium` branch. Companion web change: the three B2 feature
keys (`lock_modes`, `usage_stats`, `pomodoro`) were appended to
`PREMIUM_FEATURES` *before* the keypair ceremony (grepfocus-web `e511270`)
so every token ever minted carries all seven keys.

## Decisions baked in

1. **License checks gate config/save/schedule-fire/activation time only** —
   active enforcement is never torn down or weakened mid-block by expiry or
   license removal (akrasia model wins; matches the fail-open philosophy).
2. **Clock rollback**: `high_water_unix` in state (highest time ever
   observed, bumped in-memory each tick, persisted opportunistically);
   `effective_now() = max(now, high_water)` for all expiry checks. Startup
   bumps the mark *before* verifying the stored token.
3. **DoH/nft blocking and the settings password stay FREE** — without the
   DoH table, free hosts-blocking is trivially defeated by Firefox defaults.
   `tamper_protection` gates only the trailing `chattr +i` ("content is
   enforcement, the bit is hardening"). The bit is never proactively cleared
   for license reasons; it catches up on the next natural re-apply.
4. **Downgrade deletes nothing**: saved blocks stay visible and startable
   (StartBlock/TakeBreak/deletes ungated); the 1-block cap hits only NEW
   adds; schedules stop firing new windows (in-flight windows run to
   completion); app enforcement snapshots into `ActiveBlock.apps_enforced`
   at activation, so `SetLicense` can never be a mid-block bypass lever —
   and SetLicense itself sits behind the settings lock for the same reason.
5. **Grandfathering**: UpdateBlock may keep or clear an existing apps list
   without a license, but not introduce or modify one (editing domains on a
   premium-era block must not brick it).
6. **Verification is over opaque bytes**: the signature covers the base64url
   payload segment exactly as received — never re-serialized claims (JSON is
   not canonical). Both segments base64url no-pad; padded input rejected.

## What shipped (all commits gated on ./scripts/check.sh)

- `561d6ca` core: license module (verify_token, error taxonomy
  Malformed/BadSignature/Expired with GUI-facing Display, 7 feature consts)
- `a62660c` core: JS↔Rust known-answer vectors minted through the real
  web-side `signLicense()` (tampered/wrong-key/padded/structural/mutation
  sweep/unknown-claim cases; generator preserved in the test header)
- `d974d7e` core: embed the production public key (first ceremony)
- `c5b8ab0` core: **rotate the key** — the first private key leaked into
  tooling transcripts (truncated command-line paste, trivially recoverable)
  and was burned; free pre-sales, catastrophic after. Lesson recorded below.
- `6f2b846` core: production-key KAT vector — an expired trial signed by the
  vaulted key: fully verifies at its 2000-01-01 boundary (happy path under
  the production key) and fails only `Expired` after it
- `8439bd3` daemon: license_token + high_water_unix in state; fail-open
  startup verification (bad token → warn + run unlicensed, never crash,
  never strip)
- `729f29b` daemon: SetLicense IPC (verify-before-store, settings-lock
  gated) + six `license_*` Status fields re-checking expiry at status time
- `63db1a1` daemon: the gates — AddBlock cap, app-list gating with
  grandfathering, schedule add/update + fire-time gate (skips logged once
  per window occurrence, keys pruned), chattr-only tamper gate,
  apps_enforced snapshot consumed by procwatch
- `c6d8e1e` gui: license tab (paste/activate/remove through the unlock
  flow; renders free/perpetual/trial-with-expiry/present-but-invalid; the
  daemon stays the validity authority)

## Live verification (Fedora 44, 2026-07-11, daily driver)

| Check | Result |
|---|---|
| Trial activation via GUI (production key happy path) | PASS |
| Multiple saved blocks + schedule adds while licensed | PASS |
| License removal via GUI and via IPC | PASS |
| Active blocks run to completion after removal | PASS |
| Downgrade deletes nothing; saved blocks stay startable | PASS |
| 1-block cap on new adds (exact planned copy) | PASS |
| App-list add and schedule add gated (exact copy) | PASS |
| Free tier: hosts content enforced, no `+i`, "without tamper protection" info log | PASS |
| Licensed apply sets `+i` (on the next union change — not retroactively on install) | PASS |
| `+i` survives license removal (never proactively weakened) | PASS |
| `apps_enforced` snapshot visible on active records | PASS |
| Schedule fire skipped when unlicensed, logged exactly once per window (1 entry after 8+ in-window ticks) | PASS |
| Malformed IPC frame (wrong AppMatcher tag) dropped without daemon harm | PASS (incidental) |

## Operational lessons

- **Never put the signing key on a command line.** The first ceremony key
  was burned when a paste landed in tooling transcripts and shell history.
  Mint pattern: `read -rs LICENSE_SIGNING_KEY && export ...` (silent
  prompt), run the mint script, `unset`. Rotation is free only while zero
  licenses exist.
- `buildClaims()` derives timestamps from `Date.now()` — KAT fixtures must
  build claims literally and call `signLicense()` directly.
- `lib/license.ts` imports `./features` extensionless; Node's
  `--experimental-strip-types` needs a `registerHooks` resolve fallback to
  import it from a script (see the KAT test header).
- A license install alone never rewrites /etc/hosts (the memo ignores it);
  the `+i` appears on the next union change or drift re-apply. Expected, by
  design — worth remembering during support.

## Not in this milestone

B2 capabilities (`lock_modes`, `usage_stats`, `pomodoro` — keys already in
every token; each gets its own plan), Track A (.rpm + release, paused
mid-flight on master), online device-cap validation (stateless offline
tokens by design), GUI feature-gate awareness beyond error messages (the
GUI shows daemon errors verbatim; preemptive disabling of gated UI is
future polish).
