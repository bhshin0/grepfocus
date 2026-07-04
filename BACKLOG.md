# Known issues / backlog

Low-severity findings from the 2026-07-04 adversarial code review. Each was
independently verified as real. File:line references are as of commit
`77a2e92` (pre-fix-wave; may have shifted since).

The daily-driver hardening milestone (see `docs/plans/dailydriverhardening.md`)
resolved most of these across Phase 1 (durability, commit `43fd859`) and
Phase 2 (backlog lows). Status is tracked inline below.

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
  "Frostbite — daemon unreachable" (without touching the notification
  baseline `prev`).

## Decisions

- **frostbite → Timely rename: DEFERRED (2026-07-04).** Everything keeps its
  current names: crates `frostbite-core`/`frostbited`/`frostbite-gui`, group
  `frostbite`, socket `/run/frostbite/sock`, nft table `frostbite_doh`, hosts
  markers `# frostbite-begin`/`# frostbite-end`, paths `/var/lib/frostbite`,
  `/etc/frostbite`. Rename cost grows with each new artifact; the daily-driver
  milestone added `frostbite.desktop`, `hosts.orig`, and `upgrade.sh`. Revisit
  before publishing beyond the author's machine.
