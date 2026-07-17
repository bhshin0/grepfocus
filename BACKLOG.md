# Known issues / backlog

Low-severity findings from the 2026-07-04 adversarial code review. Each was
independently verified as real. File:line references are as of commit
`77a2e92` (pre-fix-wave; may have shifted since).

The daily-driver hardening milestone (see `docs/plans/dailydriverhardening.md`)
resolved most of these across Phase 1 (durability, commit `43fd859`) and
Phase 2 (backlog lows). Status is tracked inline below.

The *Bookmarks* section at the end collects deferred research notes — not
review findings — so they don't have to be re-derived later.

## Daemon

- **[FIXED — Phase 2] Gated config arms mutate before save without rollback** —
  `crates/daemon/src/ipc.rs` (AddBlock/UpdateBlock/DeleteBlock/AddSchedule/
  UpdateSchedule/DeleteSchedule). On `state::save` failure the in-memory
  mutation survived while disk kept the old state; a later unrelated save
  silently committed it. All six arms now snapshot the affected collection
  (and its id counter) before mutating and restore it on save failure, matching
  StartBlock/TakeBreak/SetPassword.
- **[FIXED — Phase 2] Argon2 runs synchronously under the state mutex** —
  `crates/daemon/src/ipc.rs` (Unlock/SetPassword). Each verify/hash stalled the
  scheduler tick, procwatch, and all IPC for the hash duration. Both arms now
  clone the PHC string, drop the lock, and run verify/hash in
  `tokio::task::spawn_blocking`. SetPassword re-acquires the lock afterward and
  rejects the change if the stored hash moved during hashing
  ("password changed concurrently").
- **[FIXED — Phase 2] Responses can exceed MAX_FRAME (1 MiB)** —
  `crates/core/src/wire.rs`. A very large block list made `write_json` fail and
  dropped the connection with no Response. `MAX_FRAME` is now 16 MiB, and
  `ipc::handle` responds with `Error { "response too large" }` on
  `InvalidData` (the stream is intact because `write_json` size-checks before
  writing any bytes) instead of dropping the connection.
- **[FIXED — Phase 1, `43fd859`] Crash window between the two renames in
  `state::save`** — `crates/daemon/src/state.rs`. A crash after `state.json`
  was renamed but before `state.json.mac` made the next startup treat state as
  corrupted and start fresh (wiping blocks/schedules/password). State is now a
  single file (32-byte HMAC prefix + JSON body) written with one fsync+rename;
  the legacy two-file layout is still read for automatic migration.
- **[WONTFIX] TakeBreak residual: persistent enforce failure keeps the ledger
  charge** — `crates/daemon/src/ipc.rs`. Save-path rollback and retrying
  `enforce::sync` (scheduler self-heal) are in place, so this only matters if
  applies fail persistently for the whole break. A refund would require
  tracking whether a break ever took effect; deliberately not worth it for the
  single-user akrasia threat model.

## GUI

- **[FIXED — Phase 2] Concurrent `ensureUnlocked()` calls clobber
  `unlockResolver`** — `crates/gui/ui/src/main.ts`. Two gated actions racing
  each other leaked the first promise (its action silently never ran).
  `promptUnlock` now shares a single in-flight `unlockPromise`; `finishUnlock`
  clears both it and `unlockResolver`.
- **[FIXED — Phase 2] Stale tray tooltip while the daemon is down** —
  `crates/gui/src/main.rs` (status watcher `continue` on poll failure). The
  tooltip kept reporting the last-known "N active". On poll failure it now sets
  "GrepFocus — daemon unreachable" (without touching the notification
  baseline `prev`).

## Decisions

- **Rename to grepfocus: DONE (2026-07-10).** Deferred on 2026-07-04 (then
  targeting "Timely") because rename cost grew with each new artifact;
  executed 2026-07-10, before `.rpm` packaging could multiply the cost
  further. Display name **GrepFocus**; binaries and paths all-lowercase.
  Renamed: crates `grepfocus-core`/`grepfocusd`/`grepfocus-gui`, group
  `grepfocus`, socket `/run/grepfocus/sock`, nft table `grepfocus_doh`,
  hosts markers `# grepfocus-begin`/`# grepfocus-end`, paths
  `/var/lib/grepfocus` (incl. `hosts.orig`) and `/etc/grepfocus`,
  `grepfocus.desktop`, unit `grepfocusd.service`, GitHub repo
  `bhshin0/grepfocus`. See *Bookmarks → Rename* below for the naming
  research trail.

## Bookmarks (deferred work)

Research notes only — nothing below is scheduled or implemented unless
marked fixed inline. Each entry records findings so the legwork doesn't have
to be redone when the item is picked up.

- **[DONE — `premium` branch, 2026-07-11] Licensing / paywall** — implemented
  and live-verified per `docs/plans/premium-licensing.md` (v1 on master still
  ships free; the branch merges when the sell decision lands). The research
  notes below are kept for reference; the keypair ceremony is DONE (key
  vaulted; the first key was rotated after a transcript leak — never put the
  signing key on a command line). Original bookmark: app-side integration
  spec from the frostbite-web audit (the external store repo; renaming it to
  match grepfocus is future work). Token format:
  `base64url(JSON claims) + "." + base64url(raw 64-byte Ed25519 signature)`;
  the signature is computed over the ASCII bytes of the FIRST base64url
  segment (JWT-style), NOT the decoded JSON; both segments are base64URL
  no-pad. Claims (field names frozen): `license_id`, `email`, `tier`
  (`"premium"`), `kind` (`"perpetual"` | `"trial"`), `features` (string
  array: `app_blocking`, `schedules`, `tamper_protection`,
  `unlimited_blocks`), `issued_at`, `expires_at` (unix seconds, or null =
  perpetual), `max_devices`. Public key: the raw 32 bytes from
  frostbite-web's `pnpm gen-keypair` (`PUBLIC_KEY_BASE64URL`), embedded in
  `crates/core`; the keypair is a one-time ceremony — rotation invalidates
  every sold key. Verification and feature gating must live daemon-side
  (the GUI is unprivileged and spoofable). Needs: `ed25519-dalek` v2 in
  crates/core, a `SetLicense` IPC arm plus license fields in `Status`,
  `license_token` in persisted `State` (re-verified on load), a GUI license
  tab, and a committed JS<->Rust known-answer test vector (one encoding
  mismatch = every real key rejected). Open decisions recorded: mid-block
  trial expiry policy (akrasia says finish the block, paywall says stop);
  clock-rollback high-water mark; gating map free = hosts blocking + manual
  blocks + 1 saved block / premium = app_blocking + schedules +
  tamper_protection + unlimited_blocks (per frostbite-web
  `lib/features.ts`).
- **[DONE — `premium` branch, 2026-07-16] Lock modes (B2.a)** — implemented
  and live-verified per `docs/plans/premium-lock-modes.md`. Per-block
  `LockMode` (`normal`/`password_breaks`/`challenge_breaks`), gated at save
  time, enforced from an `ActiveBlock.lock` activation snapshot so a mid-block
  edit or downgrade can only make a running block stricter, never weaker.
  Break decision is license-free (mode licensed at save). Challenges are
  daemon-issued (40 chars, unambiguous alphabet), trimmed + case-sensitive
  match, single-use, and retired when the block deactivates
  (`prune_break_challenges`). No `NoBreaks` variant — `allowance == 0` already
  gives that free. Remaining B2: `usage_stats`, `pomodoro`.
- **[DONE — `premium` branch, 2026-07-17] Usage stats (B2.b)** — implemented
  and live-verified per `docs/plans/premium-usage-stats.md`. Option A scope:
  focus history, app-block kills (PID-deduped), breaks taken/**refused**, and
  derived streaks — NOT per-domain attempt counts (unobservable without a DNS
  proxy; rejected as disproportionate for an akrasia-only tool). `UsageStats`
  lives in `State` (HMAC-protected, bounded by a 200-session ring + 365-day
  retention). Recording is always on and daemon-side; only the `GetUsageStats`
  read is gated on `usage_stats`. Store copy reworded (grepfocus-web
  `e89fa9a`). Remaining B2: `pomodoro`.
- **[DEFERRED] Packaging** — `.rpm` first. Use `sysusers.d`/`tmpfiles.d`
  for the group and runtime/state dirs; declare runtime deps (webkit2gtk4.1,
  libappindicator/ayatana); `%preun` can run `grepfocusd cleanup` verbatim.
  `tauri.conf.json`'s bundle section is currently disabled. The store
  download page artifacts are all "coming soon" placeholders.
- **[FIXED — renamed to grepfocus, 2026-07-10] Rename** — research
  2026-07-06, resolved 2026-07-10: the project is now **grepfocus** (display
  name **GrepFocus**), collision-checked clean — crates.io free, no product
  conflicts (GuruFocus is unrelated finance software). Research kernel: the
  original name carried medium-high trademark risk (EA's game engine of the
  same name, Class 9 overlap) — fine at low visibility, but wrong to build
  paid brand equity on. "Timely" (the 2026-07-04 candidate): effectively
  taken — timely.com productivity SaaS plus the well-known `timely` crate —
  dead. "Frostlock": the earlier researched-CLEAR candidate; "Hoarfrost":
  clear backup (spelling friction); grepfocus won. The rename covered:
  crate/binary names, systemd unit, socket path `/run/grepfocus`, unix
  group, hosts markers, nft table name, `/var` + `/etc` dirs,
  `.desktop`/icon, Tauri identifier, GitHub repo.
- **[FIXED — UX polish] GNOME tray invisibility** — stock GNOME ships no
  StatusNotifier host, so the tray icon never appeared and close-to-tray made
  the app invisible after its first close. The GUI now probes for a host at
  close time (quit when none, hide to tray when present), and the status
  watcher re-shows a hidden window if the host vanishes.
- **[FIXED — UX polish] First-run error copy** — the GUI surfaced the raw
  connect errno when the daemon was down or the user wasn't in the
  `grepfocus` group. Connect failures now say what to do instead
  (start/install the daemon; `usermod` + re-login), with the raw error kept
  as a trailing line.
