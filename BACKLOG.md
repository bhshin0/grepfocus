# Known issues / backlog

Low-severity findings from the 2026-07-04 adversarial code review. Each was
independently verified as real. File:line references are as of commit
`d1748b3` (pre-fix-wave; may have shifted since).

The daily-driver hardening milestone (see `docs/plans/dailydriverhardening.md`)
resolved most of these across Phase 1 (durability, commit `818b8c4`) and
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
- **[FIXED — Phase 1, `818b8c4`] Crash window between the two renames in
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

## Input hardening, health, DoH policies, updates (2026-09-28)

Status: **implemented, live verification and release pending** — all seven
work packages landed on `hardening-health`: WP1 (core validators,
`State::sanitize`, health wire types), WP2 (daemon + GUI input hardening,
procwatch guards), WP3 (daemon health state, `get_status.health`,
`grepfocusd --version`, GUI pass-through), WP4 (daemon `browser_policy`
module, cleanup/uninstall parity), WP5 (Status-tab health banner, tray RED
notification, Settings about/diagnostics lines, `grepfocus-gui --version`),
WP6 (GUI/daemon skew advice, AppImage "Update system service", installer
under bash with package/downgrade guards) and WP7 (daily release check with
a one-time disclosure and a Settings opt-out, `open_url`, `xdg-utils`
Recommends). Design record: `docs/plans/hardening-health-updates.md` — its
live verification checklist is still to be run. Pending release-note lines
(the next `Release x.y.z` commit owns the changelog files):

- Browsers' DNS-over-HTTPS is now switched off through standard
  enterprise-policy files (Firefox, Mullvad Browser, Chromium, Chrome, Brave)
  so blocks apply in them; those browsers show a "managed by your
  organization" notice and must be restarted once. DoH stays off while
  GrepFocus is installed (Mullvad Browser then uses the OS resolver instead
  of Mullvad DNS); `grepfocusd cleanup` or uninstalling restores the files.
  Downgrading: remove the files first (README → Recovery).
- The Status tab now reports enforcement problems (failed `/etc/hosts`
  write, failed or stale DoH table, tamper protection off, browser policy
  failures, instant-break proxy) with a desktop notification on a new
  failure; the Settings tab shows the app and service versions plus a
  diagnostics line; `grepfocusd --version` and `grepfocus-gui --version`.
- Block content is validated: domains must be hostnames (URLs are trimmed to
  the hostname; IP literals, wildcards and single labels are refused), app
  matchers must be well-formed and may not target GrepFocus itself, a block
  needs at least one domain or app; stored entries are canonicalized at
  startup and unusable legacy entries are dropped with a journal warning.
- App blocking never kills root processes (system services, `sudo`/`pkexec`-
  launched apps) or GrepFocus itself.
- AppImage: the Status tab offers "Update system service" when the app is
  newer than the installed service; the installer runs under bash (fixes the
  first-run install on Debian/Ubuntu), refuses to run over a package install
  and refuses downgrades.
- The app checks grepfocus.com once a day for a newer release (version
  number only; one-time disclosure; opt-out in Settings).

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
- **[DONE — 2026-07-17] Packaging (.rpm + .deb)** — native packaging for both
  Fedora and Ubuntu, on `master`. RPM: `packaging/grepfocus.spec` +
  `build-rpm.sh` (archives HEAD, rpmbuild; toolchain from the user's PATH, no
  rust/pnpm BuildRequires). DEB: `debian/` (dh, compat 13) built via
  `packaging/build-deb.sh` inside an `ubuntu:24.04` podman container
  (`packaging/deb/Containerfile`) so the GUI links Ubuntu's libraries — a
  Fedora-built binary won't run on Ubuntu. Both reuse the same
  systemd unit/sysusers.d/tmpfiles.d; both tear down via `grepfocusd cleanup`
  on erase/remove while the binary still exists. Gotcha recorded:
  `dh_installsysusers` is NOT in the compat-13 dh sequence, so the deb creates
  the group in `debian/grepfocus.postinst` (before the service starts) rather
  than via a staged sysusers file. Both verified installing cleanly in clean
  containers; outputs `dist/grepfocus.rpm` and `dist/grepfocus.deb`. STILL
  user-side to actually ship: make the GitHub repo public, cut a Release and
  upload both artifacts, and point the store download links at them (the store
  hardcodes `releases/latest/download/grepfocus.rpm`; add the `.deb`).
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
- **[DONE — `premium` branch, 2026-07-17] Pomodoro (B2.c)** — implemented and
  live-verified per `docs/plans/premium-pomodoro.md`. A session drives one
  saved block through focus/break cycles (new `Originator::Pomodoro`), reusing
  the `ActiveBlock` machinery; auto-breaks set `break_until_unix` directly
  (free, no allowance charge). HYBRID commitment: a focus interval can't be
  interrupted, `StopPomodoro` allowed only during a break — surfaced clearly in
  the GUI. `StartPomodoro` gated on `pomodoro` + bounds-checked; manual breaks
  refused on a pomodoro block; one break-inclusive `origin=pomodoro` session
  recorded at end via the reconcile step-1 choke point. **Completes Track B
  (B2.a/b/c) — all 7 premium feature keys now have app-side implementations.**
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
- **Flatpak Firefox DoH policy** — `browser_policy` reports the Flatpak
  Firefox (`/var/lib/flatpak/app/org.mozilla.firefox`) as `unsupported`.
  The supported route is the `org.mozilla.firefox.systemconfig` extension
  (`/var/lib/flatpak/extension/org.mozilla.firefox.systemconfig/x86_64/stable/policies/policies.json`,
  the path the daemon already reports); it needs a Flatpak Firefox on hand
  to verify the mount and which extension branch the app actually reads.
- **Snap browsers, Chrome, Brave: live verification** — the Chromium snap
  path (`/var/snap/chromium/current/policies/managed/grepfocus.json`), the
  Firefox snap (reads `/etc/firefox/policies/policies.json` like the rpm —
  assumed, not verified) and the Chrome/Brave managed dirs are written from
  documentation only; verify on an Ubuntu VM with each installed.
- **Vivaldi / Edge / Opera managed dirs** — `/etc/vivaldi/policies/managed`,
  `/etc/opt/edge/policies/managed`, `/etc/opt/opera/policies/managed` are
  the documented locations; adding a target is one row in
  `browser_policy::targets` plus the uninstall.sh mirror (the parity test
  fails until both are done).
- **`Settings.browser_policies` opt-out** — v1 writes the policies
  unconditionally (free tier). A toggle would need the setting on the wire,
  a password gate like the other settings, and `remove_all` on the off
  edge.
- **`/etc/mullvadbrowser/...` is never read** — Mullvad Browser starts with
  `MOZ_SYSTEM_POLICIES=false`, so the only policy source is
  `/usr/lib/mullvad-browser/distribution/policies.json`. Do not retry an
  `/etc` path for it.
- **Multi-user procwatch scoping** — app matchers apply to every non-root
  process on the machine, whoever owns it (README → *Known limits*). The
  fix is to record the requesting uid on `ActiveBlock` (`SO_PEERCRED` on
  the accepted socket — `UnixStream::peer_cred`; nothing reads it today,
  the group on the socket file is the whole authorization) and have
  `procwatch::sweep` compare it against the process's effective uid; the
  guard set (`is_protected`) stays as is. Needs a decision on schedules and
  pomodoro activations, which have no requesting client.
- **Save-time breadth check for app matchers** — a `cmdline:` pattern such
  as `cmdline:bin` is well-formed but matches nearly every process,
  including the desktop session (README → *Recovery* has the escape). The
  daemon could count the processes currently matching a new or changed
  matcher at `AddBlock`/`UpdateBlock` time and refuse above a threshold (or
  when it would hit the caller's own session). Reads `/proc` under the IPC
  lock, so it needs the same `spawn_blocking` treatment as Argon2.
- **`GREPFOCUS_NO_UPDATE_CHECK` packager kill switch** — a distro that
  forbids phoning home has no build- or install-time way to turn the daily
  release check off; today it is the per-user Settings toggle only. An
  environment variable (or a file under `/etc/grepfocus`) read in
  `update::Store::open` that forces `enabled: false` and hides the toggle
  and the disclosure strip would do; decide whether it also hides the
  Settings row.
- **Version-mismatch YELLOW in `healthNotices`** — when both versions are
  known but differ, a one-line rule in `healthNotices` would put the skew
  in the health banner too. The Status tab's skew card (`#update-banner`)
  already covers differing versions with the remedy, so this is only worth
  it if the card proves easy to overlook.
- **Read-only `~/.config` and the update-check opt-out** — the preference
  lives in `~/.config/grepfocus/update-check.json`. If it cannot be written
  the opt-out holds for the session only (Settings says "could not be
  saved"), and the next launch starts from the defaults: checks on, the
  disclosure strip shown again. A file that exists but cannot be read
  fails closed; a directory that never accepts the file cannot.
- **Release-check disclosure is a notice, not a prompt** — the first
  request goes out about 3 s after the strip is shown, clicked or not
  (README → *Update notifications* says so); "Turn off" is a refusal only
  inside that window. Holding the first request until "Got it" would make
  it a real choice, at the price of never checking where the strip is
  ignored. Owner decision, tied to open question 3 of
  `docs/plans/hardening-health-updates.md` (default on vs opt-in).
- **`min_supported` / `security` flag in `latest.json`** — the contract
  carries `version` only, so a dismissed release stays dismissed even when
  it fixes a bypass. A flag the client treats as undismissable (and a
  floor below which the notice cannot be dismissed) needs a website change
  and a `Release` field; unknown fields are already ignored, so old
  clients are unaffected.
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
