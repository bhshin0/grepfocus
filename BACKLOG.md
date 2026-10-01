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
- **[VERIFIED — 2026-09-30; the owner's live check passed: AppIndicator
  extension off, then on → icon and a working menu back within ~10 s]
  Tray icon reported lost after the tray host restarts** —
  `crates/gui/src/tray.rs` (`probe_host`, `TrayWatch`),
  `crates/gui/src/main.rs` (`reregister_tray`). Reported: after the
  StatusNotifier host went away and came back (GNOME: the AppIndicator
  extension disabled and re-enabled, or updated), the icon stayed gone until
  the app was relaunched, with the app still running hidden. This has not
  been reproduced, and the evidence below says the item normally comes back
  by itself — so the entry stays open until the live check says whether the
  icon is ever actually missing under a returned host.
  What is known:
  - libappindicator (libayatana-appindicator 0.6.0) registers the item by
    itself each time the watcher name appears, also when no host existed at
    startup. It makes that call once per appearance and does not retry after
    an error reply (seen in an isolated session; it prints `Unable to connect
    to the Notification Watcher` when that happens).
  - Nothing shows that error ever happening against the real extension. On
    the dev machine the user journal carries the GUI's stderr (its other
    libayatana and GTK warnings are there) from 2026-07-11 on, and has no
    `Unable to connect to the Notification Watcher` line from any process and
    no extension message naming the item (`tray_icon_tray_app_…`), while host
    restarts were routine (every screen lock, see the next entry).
  - Extension v66 (`statusNotifierWatcher.js`): an item is stored before the
    steps that can throw and stays stored after a throw; every stored item is
    listed in `RegisteredStatusNotifierItems`; a repeated registration of a
    stored item only resets it and creates no icon; and 2 s after each enable
    the extension scans the bus and registers any item it does not hold
    ("Using Brute-force mode"). So on this host a registration that was
    rejected leaves the item listed without an icon, and registering again
    does not repair that.
  - The one incident on record — `gnome-extensions disable … && enable …` in
    one line — left no tray host at all, which is a different failure.
  What the change does: the 5 s status watcher reads the watcher's
  properties on every poll (one `busctl call … Properties.GetAll`, where it
  used to read one property and only while the window was hidden).
  - On the host's absent→present edge (the first poll is a baseline) it
    re-sets the tray menu after the same 1.5 s delay as at startup. That
    re-applies the blank-menu workaround to the new host and makes
    libappindicator register again.
  - While the host stays up and does not list the item (a registration that
    never arrived or was refused outright, or a restart that fit between two
    polls), it re-sets again on that poll — three attempts, then one log
    line, a hidden window is shown once (the tray cannot be trusted to bring
    it back), and nothing more until the host next restarts. A listing that
    cannot be read counts as unknown, not as missing. A re-set that fails on
    the GUI's side is logged once and retried the same way.
  - One action per poll at most. Startup and the re-set share one path
    (`build_tray` once, `reregister_tray` for the menu swap).
  What it does not do:
  - Recover an item the host has recorded and failed to show (the extension
    case above): the item is listed, so nothing retries, and a retry would
    only be a reset. That would need the host to drop the item first — a new
    object path, or the item's bus name going away.
  - Notice a host restart that fits between two polls when the item's own
    registration is accepted: no edge, the item is listed, so no menu re-set
    for the new host (a lock/unlock under 5 s is such a restart). Polling
    cannot see it — on GNOME the name's owner is gnome-shell before and
    after. Only a `NameOwnerChanged` subscription would; `gio` and `zbus`
    are already in `Cargo.lock` as transitive dependencies, a direct one is
    the owner's call.
  - Stop treating "host present" as "tray usable" at close time after the
    give-up: closing still hides. Quitting instead would take hide-to-tray
    away on any host whose listing is readable but formatted unexpectedly.
  - Remove the tray and build a new one. The libappindicator Rust wrapper
    never unrefs the C object, so the removed item and its DBusMenu stay
    exported, the replacement fails to export under the same id, and the
    host is left with the old item — passive, empty menu (tried; see
    `docs/plans/uxpolish.md`).
  Verified (private `dbus-run-session`, headless mutter, a stub
  `org.kde.StatusNotifierWatcher`; closes injected through mutter's
  RemoteDesktop API; menu clicks sent over DBusMenu): host restart; host
  appearing after startup; a watcher without a host replaced by one with a
  host; a restarted stub that refuses the first registration outright and
  does not list the item (the build without this change did not register
  again in 20 s, this one did ~6 s after the host returned); three restarts
  in 4 s (one extra registration); both listing formats (bus name + path,
  bare path); a host that never lists the item (three retries, the log line,
  and a window hidden in the tray came back); a listing property that errors
  (no retries, close still hides); a steady host (the two startup
  registrations, as before). Except where noted the item ended `Active` with
  the three-entry menu and "Quit" / "Show GrepFocus" worked. Close with a
  host hides, close without one quits, a hidden window comes back when the
  host goes, a second launch exits — unchanged.
  Verified not to help (same session, stub switched to the extension's
  semantics: a refused item stays stored and listed, a repeat is a reset):
  after a restart with a refused first registration the item stayed listed,
  the edge re-set was answered as a reset, and no further attempt followed.
  Not verified: anything on the real extension — whether the icon and its
  menu render after a host return, with or without this change — and any
  host other than the stub.
  No README sentence until the live check shows a difference a user would
  see. The release-note line is drafted with the other pending lines below
  ("If the system tray restarts …") and rests on the same check: drop it
  from the notes if steps 1–2 show no such difference.
  **Live verification (owner):** run the new build, close the window to the
  tray, then:
  1. Extension toggle. Turn the AppIndicator extension OFF (Extensions app,
     or `gnome-extensions disable appindicatorsupport@rgcjonas.gmail.com`).
     The window should reappear within ~10 s (hidden-window rescue, two
     polls since the next entry's change). Wait 10 s more, then turn the
     extension ON as a SEPARATE command or click — never
     `disable … && enable …` in one line; that once left no tray host at
     all. Within ~10 s the icon should be back with a working menu ("Show
     GrepFocus" and "Quit" both visible and both doing their job), and
     closing the window should hide it to the tray again.
  2. Quick toggle. OFF, then ON within 5 s (still two separate commands).
     Icon back? Menu populated, or blank? This is the between-two-polls gap.
  3. Screen lock: the live check of the next entry (it covers the icon and
     its menu after the unlock as well).
  4. If the icon is ever missing while the extension is on, capture before
     relaunching:
     `busctl --user call org.kde.StatusNotifierWatcher /StatusNotifierWatcher org.freedesktop.DBus.Properties GetAll s org.kde.StatusNotifierWatcher`
     and
     `journalctl --user -b -g 'Notification Watcher|appindicator|grepfocus-gui'`.
     An item that is listed but invisible means the recovery has to make the
     host drop the item, not register it again.
  Steps 1–3 on the previous build as well would show whether the icon was
  ever lost without this change.
- **[FIXED — 2026-09-30; verified headless and against the dev machine's
  real lock state, the owner's live check is pending] Locking the screen
  re-showed a window hidden in the tray** — `crates/gui/src/tray.rs`
  (`session_locked`, `rescue_action`, `RescueWatch`),
  `crates/gui/src/main.rs` (status watcher). Observed on the dev machine
  with the screen locked: `org.gnome.ScreenSaver.GetActive` true, the
  AppIndicator extension `Enabled: Yes` / `State: INACTIVE`, and no
  `org.kde.StatusNotifierWatcher` on the bus (the extension declares no
  `unlock-dialog` session mode, so GNOME Shell disables it while locked; its
  source calls out "entering/leaving the lock screen"). Locking is the
  everyday host restart. By the code, every lock longer than one poll made
  the hidden-window rescue (`!probe.host` → `show_main_window`, which also
  focuses) re-show a window that was hidden in the tray, undoing
  hide-to-tray; that was never seen with the owner's eyes, and the old build
  was not run against a lock here.
  What the change does:
  - The rescue is now a pure decision, `tray::rescue_action(hidden,
    host_present, locked, absent_polls)`, counted by `RescueWatch`. While
    the session is locked a missing host never shows the window. Unlocked,
    the host has to be missing on 2 polls in a row (it leaves a moment
    before the lock is reported, and a poll landing in between must not show
    the window); with a lock state that cannot be read, on 3 (nothing then
    tells a lock from a dead host, so this only absorbs a read that failed
    once or twice and a host restart — a lock longer than about 15 s shows
    the window as before). A locked poll starts the count over, so a host that
    is still gone after the unlock is rescued 2 polls later.
  - The lock state is `LockedHint` of the logind session, read with
    `busctl --system call … /org/freedesktop/login1/session/auto
    org.freedesktop.DBus.Properties Get` (the `call` verb for the same
    reason as the tray probe). `auto`, not `self`: read from an app scope
    under the user manager — where a GUI the desktop launched runs —
    `session/self` answers "Unknown object" and `session/auto` resolves to
    the graphical session (its `Id` came back as the Wayland session's).
  - When the hint does not say "locked", `org.gnome.ScreenSaver.GetActive`
    on the user bus is asked too. GNOME's screen shield also comes up, and
    takes the extensions down, without locking: on idle, until the lock
    delay has run out, or for good with automatic locking off. That is
    from GNOME Shell 50's `screenShield.js` (`activate()` pushes the
    `unlock-dialog` mode; only `_setLocked` sets the hint; on idle `lock()`
    runs after the lock delay and only with `lock-enabled`) — read, not
    exercised. Off GNOME the call fails and the hint alone decides.
  - Both reads happen only on a poll that finds the window hidden and the
    host missing: no extra process otherwise, one or two then.
  - Unchanged: the tray probe and `TrayWatch` run on every poll, so the
    host's return after an unlock still re-sets the menu; the give-up path
    still shows a hidden window at once.
  What it costs: a tray host that really goes away (the extension turned
  off) brings the window back after two polls, 5–10 s, where it was one.
  README → *Known limits* says "~10 seconds" and that locking does not count.
  Verified:
  - Unit tests for the two reply shapes, for which source may say "locked",
    and for the decision and its counter (lock, unlock with the host back,
    unlock with the host still gone, host lost while unlocked, unreadable
    state, a failed read between locked polls).
  - Read-only on the dev machine, screen locked, GNOME's default lock
    settings (`lock-delay` 0, `lock-enabled` true): the exact command the
    GUI runs returned `v b true`, `GetActive` returned `b true`, no watcher
    was on the bus.
  - The GUI run headless (private `dbus-run-session`, headless mutter, a
    stub `org.kde.StatusNotifierWatcher`, HOME and XDG dirs on a temp dir).
    Whether the window is on screen was probed with Alt+F4 through mutter's
    RemoteDesktop API while no host was up: a visible window then quits the
    app, a hidden one does not get the key. With the real `busctl` and the
    dev machine's real (locked) session: window hidden, host stopped, 7
    polls, still hidden; one `LockedHint` read per poll and no
    `GetActive`. With a `busctl` wrapper that answers only the two lock
    reads from a file and passes everything else on:
    - locked, host gone for 32 s: still hidden. Then unlocked with the host
      back: the item registered with it and the menu re-set followed on the
      next poll (two registrations), still hidden. Then the host stopped
      again, unlocked: shown after 2 polls.
    - host lost while locked and still gone after the unlock: hidden 1 poll
      after the unlock, shown after 2.
    - unlocked, host stopped: hidden after 1 poll, shown after 2.
    - hint `false`, shield `true`, host gone for 32 s: still hidden; shield
      down: shown after 2 polls.
    - both reads failing: hidden after 2 polls, shown after 3.
    - no lock read before the window was hidden, nor while it was hidden
      with a host.
  Not verified:
  - The real lock screen end to end: the machine stayed locked for all of
    the above, so `LockedHint` was never read as `false` from a real
    session, the order of "host gone" and "hint set" at lock and at unlock
    was not timed, and nobody saw the window stay hidden and the icon come
    back after an unlock.
  - The shield-without-lock state on a real session (`GetActive` true with
    the hint false).
  - Any desktop other than GNOME. KDE sets `LockedHint`; whether its tray
    host leaves on lock was not looked at.
  Known gap: a desktop that leaves `LockedHint` true on an unlocked session
  would keep a window hidden whose tray host has died. Launching GrepFocus
  again shows it (single instance).
  **Live verification (owner):** run the new build, then:
  1. Close the window to the tray, lock the screen for 30 s, unlock. The
     window is still hidden, the icon is there, and its menu works ("Show
     GrepFocus" opens the window, "Quit" quits).
  2. The same with the screen left to blank by itself (idle), if automatic
     locking is delayed or off on that machine.
  3. The other direction: window hidden, AppIndicator extension turned OFF
     (step 1 of the entry above) — the window is back within ~10 s.
  If the window is on screen after an unlock, capture while locked (e.g.
  `sleep 20; …` started just before locking):
  `busctl --system call org.freedesktop.login1 /org/freedesktop/login1/session/auto org.freedesktop.DBus.Properties Get ss org.freedesktop.login1.Session LockedHint`
  and
  `busctl --user call org.gnome.ScreenSaver /org/gnome/ScreenSaver org.gnome.ScreenSaver GetActive`,
  plus `gsettings get org.gnome.desktop.screensaver lock-delay`.

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
live verification checklist is still to be run.

### Pending release-note lines (0.6.0)

Everything on this branch since the last tagged release, 0.4.0, in the
order a changelog lists it (the 0.5.0 and 0.5.1 changelog entries exist,
but no `v0.5.0` or `v0.5.1` tag does, here or on GitHub). The same ten
lines, one per line, are `docs/release-notes-0.6.0.txt` — the file for
`./scripts/bump-version.sh 0.6.0 --notes docs/release-notes-0.6.0.txt`
(`docs/release.md`, step 1); change the two together. The `Release 0.6.0`
commit owns the changelog files. Tried in a throwaway clone: the bump takes
the file as ten bullets and `--check` passes afterwards.

Two things to settle at release time:

- The first and the third line repeat what the 0.5.0 and 0.5.1 entries,
  which stay below the new one in both changelogs, already say.
- The tray line ("If the system tray restarts …") describes a mitigation
  that was never seen to make a difference on the real extension (GUI
  section above); drop it if the owner's live check shows none. The
  screen-lock line rests on the live check of that section's last entry.

- Each block's schedule card shows a compact weekly grid of its windows, and
  a new schedule takes its name from the block it belongs to.
- New ways to install: an AUR package for Arch Linux, and an AppImage that
  sets up its background service itself the first time it runs.
- Blocks now also hold in browsers that use DNS-over-HTTPS: GrepFocus
  switches it off in Firefox, Mullvad Browser, Chromium, Chrome and Brave
  through their standard policy files, and the DoH servers it blocks during
  a block now include Mullvad's and Mozilla's. Those browsers show a
  "managed by your organization" notice and need one restart; DoH stays off
  for as long as GrepFocus is installed (Mullvad Browser then uses the
  system resolver), and uninstalling puts the files back. Before downgrading
  to an older version, remove the files first (README, Recovery).
- The Status tab reports blocking problems (a change to /etc/hosts that
  could not be applied, failed DoH protection, tamper protection that is
  off, a browser policy that could not be written, the instant-break proxy)
  and a desktop notification tells you when a new one appears. Settings
  shows the app and service versions with a diagnostics line; "grepfocusd
  --version" and "grepfocus-gui --version" print them.
- Blocks are checked when they are saved: a website must be a host name (a
  pasted address is trimmed to it; IP addresses, wildcards and single words
  are refused), an app entry must be well formed and cannot target GrepFocus
  itself, and a block needs at least one website or app. Entries saved by
  older versions are tidied at startup, and ones that cannot be used are
  dropped with a warning in the system journal.
- App blocking never stops programs running as root (system services, apps
  started with sudo or pkexec) or GrepFocus itself.
- AppImage: the Status tab offers "Update system service" when the app is
  newer than the installed service, and Settings gains "Remove system
  service" (refused while a block is running; saved data is kept; if the
  service's cleanup fails nothing is removed and the app says why), so the
  service no longer outlives a deleted AppImage. The installer now works on
  Debian and Ubuntu and where /tmp does not allow running programs, and
  refuses to replace a package install or a newer service.
- The app checks grepfocus.com once a day for a newer release: only the
  version number is fetched, you are told the first time, and it can be
  turned off in Settings.
- If the system tray restarts (for example the AppIndicator extension is
  re-enabled or updated), the GrepFocus icon and its menu are set up again
  within about 10 seconds.
- Locking the screen no longer brings a window that was hidden in the tray
  back on screen.

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
  `docs/plans/hardening-health-updates.md` (default on vs opt-in — decided
  2026-09-30: default on with the strip; notice versus prompt is still
  open).
- **`min_supported` / `security` flag in `latest.json`** — the contract
  carries `version` only, so a dismissed release stays dismissed even when
  it fixes a bypass. A flag the client treats as undismissable (and a
  floor below which the notice cannot be dismissed) needs a website change
  and a `Release` field; unknown fields are already ignored, so old
  clients are unaffected.
- **Release CI: build rpm/deb/AppImage on a version tag** — a release is
  three local runs today (`packaging/build-rpm.sh`, `build-deb.sh`,
  `build-appimage.sh`; outputs in `dist/`), then a manual upload and the
  website's `latest.json`. A job triggered by a `v*` tag would build all
  three and attach them with their sha256s. What it has to reproduce: the
  rpm is built from `git archive HEAD` with the toolchain on the invoking
  user's `PATH` (the spec declares no rust/pnpm BuildRequires) and is named
  for the build host's Fedora release (`fc44`), so it needs a Fedora
  container of the advertised release; the deb and the AppImage already
  build inside podman images (`packaging/deb/Containerfile` on
  ubuntu:24.04, `packaging/appimage/Containerfile` on ubuntu:22.04, with
  `APPIMAGE_EXTRACT_AND_RUN=1` because the container has no FUSE), so those
  two port as container jobs. The job should fail when the tag and the
  workspace version in `Cargo.toml` disagree. Deferred. Since then the
  three builds and their audit have been scripted (`scripts/release.sh`,
  `docs/release.md`) and `.github/workflows/check.yml` runs the pre-flight
  checks; neither builds a package in CI.
- **A removal goes ahead after a cleanup step that only reports `FAILED`**
  — run as root, `grepfocusd cleanup` exits non-zero in two cases only
  (`crates/daemon/src/cleanup.rs`): the daemon is, or may be, still running
  (the unit is active, something accepts on its socket, or the socket
  cannot be probed), or the managed `/etc/hosts` region could not be
  removed or restored. A failed nftables
  clear, browser-policy restore, stale-temp sweep or active-block clear is
  a `FAILED` line in its summary with exit 0. The AppImage installer's
  `uninstall` stops, deleting nothing, on a non-zero or timed-out cleanup
  (exit 96, which the app reports as "The service's cleanup failed, so it
  was not removed"); after an exit-0 cleanup with a `FAILED` step it
  deletes the binary all the same. What is left then is covered by the
  manual commands in README → *Recovery*, and a policy `.orig` stays in
  `/var/lib/grepfocus/policies`. Closing it needs cleanup to tell "done,
  with failed steps" apart (a second exit status), which every caller
  would then see — decide it for all of them together.
  The rpm `%preun`, the deb `prerm` and the AUR `pre_remove` run the same
  cleanup with its status ignored (`|| :`, `|| true`) and the package is
  removed whatever it said. Left that way on purpose: pacman goes on after
  a failed `pre_remove` regardless; a failing deb `prerm` or rpm `%preun`
  does stop the removal, but it fails the whole transaction it is part of
  and leaves a package that cannot be removed for as long as cleanup keeps
  failing, with the service already stopped. (How the three package
  managers treat a failing removal script is from their documentation, not
  tried here.) README → *Uninstalling* says a failed cleanup does not stop
  a package removal and points at *Recovery*.
- **Export / import of blocks and schedules** — no way to move a
  configuration to another machine or keep a copy. Copying
  `/var/lib/grepfocus` does not work: the state file is sealed with the
  per-machine HMAC secret in `/etc/grepfocus`, so it reads as tampered
  elsewhere. Needs a daemon-side pair (`ExportConfig` → plain JSON of
  blocks and schedules only — never the password hash, the license token,
  usage stats or active blocks; `ImportConfig` behind the settings lock),
  with every imported block passed through `validate_block`, ids
  reassigned and each schedule's `block_id` remapped, and the same license
  gates as `AddBlock`/`AddSchedule` (saved-block limit, app blocking, lock
  modes, schedules) so an import cannot grant what a save would refuse.
  Open: merge versus replace, and what to do with name collisions. GUI: two
  buttons on the Block list tab and a file dialog (no dialog plugin is
  bundled today).
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
