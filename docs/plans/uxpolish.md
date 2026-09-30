# UX polish milestone — GNOME tray fallback + first-run error copy

Status: **implemented, reviewed, and live-verified** (2026-07-10).

Two daily-driver defects from the BACKLOG bookmarks:

1. **GNOME tray invisibility.** Stock GNOME ships no StatusNotifier host, so
   the tray icon (tray-icon → libappindicator, AppIndicator-only; the C lib's
   GtkStatusIcon fallback is a no-op since GNOME dropped XEmbed in 3.26) never
   renders, and the old unconditional hide-on-close stranded the app.
2. **First-run error copy.** Daemon-connect failures surfaced as raw errnos
   with no guidance for the two classic traps: daemon not running, and user
   not yet in the `frostbite` group.

## What shipped

- `c1450e3` gui: quit on close when no tray host is present — close-time
  probe over D-Bus (busctl `call` verb with `--timeout=2 --auto-start=no`;
  `get-property` silently ignores both flags and would block up to the 25s
  default) + hidden-window rescue in the 5s status watcher (a hidden window
  never gets a close event, so a tray vanishing underneath it needs the
  watcher to re-show the window)
- `e9be3c3` gui: actionable error copy for daemon connect failures —
  ErrorKind classified at the connect site only; NotFound/ConnectionRefused →
  start/install guidance, PermissionDenied → usermod + relogin; raw error
  kept as a trailing line; `white-space: pre-line` on all three surfaces
- `f105220` docs: README Known-limits bullet, BACKLOG entries flipped
- `b6ad5ec` gui: no goodbye notification on quit-close (see below)

Design decisions: detection over persisted settings (the GUI has no
persistence layer and doesn't gain one); every probe failure counts as
"no tray" — failing open to a closable window is the safe direction; the
busctl/systemd-user-bus divergence on non-systemd setups is an accepted
limitation (fails toward quit, not stranding).

## Live verification (Fedora 44, GNOME Shell 50.3, Wayland, 2026-07-10)

| Behavior | Result |
|----------|--------|
| Close with AppIndicator extension enabled | PASS — hides to tray, tray click restores |
| Close with extension disabled | PASS — app exits promptly (verified via pgrep across 5+ cycles) |
| Hidden-window rescue | PASS — window hidden in tray, extension disabled underneath it → window reappeared on its own within ~5s, process alive |
| Mid-session toggle | PASS — same launch exercised both branches (close-time detection, not startup-cached) |
| Daemon stopped (ECONNREFUSED) | PASS — "daemon is not running" copy + `(… os error 111)` on the Status tab |
| Socket chmod 600 (EACCES) | PASS — usermod/relogin copy + `(… os error 13)`; restored by daemon restart (perms reset at bind) |
| Recovery | PASS — status returns to normal on the next 5s poll after daemon start |

ENOENT (socket file removed) produces the same copy as ECONNREFUSED by
design; exercised implicitly during the matrix (unit-tested classifier).

## Findings from live testing

- **Deployment skew, again:** the first verification round ran against a
  stale binary — `upgrade.sh` had died silently at its first sudo step
  (fingerprint timeout) after the build succeeded, leaving Jul 7 binaries
  installed. Verify `/usr/local/bin` mtimes after every deploy.
- **The quit notification was tried and removed** (`b6ad5ec`): the
  notification plugin delivers on a spawned async task that process exit
  races and loses; a blocking notify-rust send instead can stall the main
  thread up to the D-Bus method timeout — observed live as a frozen window
  whose X "did nothing" — and GNOME suppresses the banner in the common case
  anyway (focused-app heuristic; the app's notification source is torn down
  at exit). The README documents quit-on-close instead of promising a
  banner.
- `systemctl start frostbited && chmod …sock` races the daemon's socket
  bind — the unit reports started before the socket exists. Test EACCES by
  chmodding the socket of an already-running daemon.

## 2026-09-30 — tray host restarts

Follow-up to the tray fallback above. The status, what was and was not
verified, the known gaps and the owner's live check are in `BACKLOG.md`
(GUI); in short, the reported "icon gone until relaunch" was not reproduced
and the change is a mitigation. What an isolated session (private
`dbus-run-session`, headless mutter, a stub StatusNotifierWatcher,
`dbus-monitor`) showed about tray-icon 0.23 / libayatana-appindicator 0.6:

- libappindicator watches `org.kde.StatusNotifierWatcher` and calls
  `RegisterStatusNotifierItem` on its own whenever the name appears, at
  startup or later. It does so once per appearance and does not retry after
  an error reply.
- `app_indicator_set_menu` runs the same registration again. The startup
  menu re-set (the blank-menu workaround) has therefore always been a second
  registration as well.
- tray-icon's `set_tooltip` is a no-op on Linux, so the tooltip text never
  reaches the host there.
- A tray cannot be rebuilt in place. `remove_tray_by_id` followed by a new
  `TrayIconBuilder` with the same id logs "An object is already exported for
  the interface org.kde.StatusNotifierItem" (and the same for
  `com.canonical.dbusmenu`): the libappindicator Rust wrapper has no `Drop`,
  the C object lives on, and what the host then reads at that path is the old
  item with `Status = Passive` and an empty menu. A new id per rebuild would
  avoid the clash but leak one exported, self-re-registering item each time.

And what the GNOME extension's source (v66, `statusNotifierWatcher.js`) and
the dev machine's bus and journal say about the real host — read from
outside, not exercised:

- The extension is disabled for as long as the screen is locked, so every
  lock/unlock is a host restart (watcher name gone, then back).
- An item is stored, and from then on listed, before the steps that can
  fail; a repeated registration of a stored item is a reset, not a new icon;
  2 s after each enable the extension scans the bus for items it does not
  hold. A rejected registration was never logged on the dev machine.

Hence the change keeps the one tray and re-sets its menu (`reregister_tray`):
on the host's absent→present edge, and while a present host does not list
the item, bounded to three attempts (`tray::TrayWatch`). On the extension the
second case only arises when the host has no record of the item; an item it
recorded and failed to show stays listed, and registering again would not
bring it back. A host restart that fits between two 5 s polls and accepts
the item's own registration is not seen at all (no menu re-set for the new
host); only a `NameOwnerChanged` subscription would close that. The tray
probe is one `busctl call … Properties.GetAll` per poll.
